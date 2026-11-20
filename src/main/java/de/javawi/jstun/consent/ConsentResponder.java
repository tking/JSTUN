/*
 * This file is part of JSTUN.
 *
 * Copyright (c) 2005 Thomas King <king@t-king.de> - All rights
 * reserved.
 *
 * This software is licensed under either the GNU Public License (GPL),
 * or the Apache 2.0 license. Copies of both license agreements are
 * included in this distribution.
 */

package de.javawi.jstun.consent;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.attribute.ErrorCode;
import de.javawi.jstun.attribute.Fingerprint;
import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.attribute.Software;
import de.javawi.jstun.attribute.Username;
import de.javawi.jstun.attribute.XorMappedAddress;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderException;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.util.Address;
import de.javawi.jstun.util.UtilityException;

/**
 * Peer-side RFC 7675 STUN Consent Freshness responder (compatible with both full ICE
 * and ICE-lite peers, RFC 7675 §1, §5.1, §5.2).
 * <p>
 * Authenticates incoming STUN Binding Requests using short-term ICE credentials and
 * responds with either:
 * <ul>
 *   <li>An authenticated STUN {@code BindingResponse} containing {@code XOR-MAPPED-ADDRESS},
 *       {@code SOFTWARE}, {@code MESSAGE-INTEGRITY}, and {@code FINGERPRINT} while consent
 *       is granted; or</li>
 *   <li>An authenticated STUN {@code BindingErrorResponse} with {@code 403 Forbidden}
 *       when consent has been revoked ({@link #setConsentGranted(boolean)} set to {@code false}),
 *       enabling immediate revocation per RFC 7675 §5.2.</li>
 * </ul>
 */
public class ConsentResponder implements AutoCloseable {
	private static final Logger LOGGER = LoggerFactory.getLogger(ConsentResponder.class);
	private static final int RECEIVE_BUFFER_SIZE = 4096;
	private static final int RECEIVE_SO_TIMEOUT_MS = 100;

	private final DatagramSocket socket;
	private final boolean ownsSocket;
	private final String expectedUsername;
	private final String password;
	private final AtomicBoolean consentGranted = new AtomicBoolean(true);
	private final AtomicBoolean silentWhenRevoked = new AtomicBoolean(false);
	private final AtomicLong requestsHandled = new AtomicLong(0L);
	private final AtomicLong revocationsSent = new AtomicLong(0L);

	private volatile boolean running = false;
	private Thread receiveThread;

	/**
	 * Creates a stateless responder for use with {@link #handleRequest(byte[], InetSocketAddress)}.
	 */
	public ConsentResponder(String expectedUsername, String password) {
		this(null, false, expectedUsername, password);
	}

	/**
	 * Creates a responder bound to a caller-supplied UDP socket (caller retains socket ownership).
	 */
	public ConsentResponder(DatagramSocket socket, String expectedUsername, String password) {
		this(socket, false, expectedUsername, password);
	}

	/**
	 * Creates a responder bound to a new UDP socket on {@code bindAddress:port}
	 * (owned and closed by this responder).
	 */
	public ConsentResponder(InetAddress bindAddress, int port, String expectedUsername, String password)
			throws SocketException {
		this(new DatagramSocket(port, bindAddress), true, expectedUsername, password);
	}

	private ConsentResponder(DatagramSocket socket, boolean ownsSocket,
			String expectedUsername, String password) {
		if (password == null || password.isEmpty()) {
			throw new IllegalArgumentException("ICE short-term password must not be null or empty");
		}
		this.socket = socket;
		this.ownsSocket = ownsSocket;
		this.expectedUsername = expectedUsername;
		this.password = password;
	}

	/**
	 * Controls whether this peer grants consent ({@code true}) or revokes it ({@code false}).
	 * When {@code false}, incoming authenticated consent checks receive an authenticated
	 * STUN {@code 403 Forbidden} response (unless {@link #setSilentWhenRevoked(boolean)} is enabled).
	 */
	public void setConsentGranted(boolean granted) {
		this.consentGranted.set(granted);
		LOGGER.info("Consent responder policy updated: consentGranted={}.", granted);
	}

	public boolean isConsentGranted() {
		return consentGranted.get();
	}

	/**
	 * When {@code true} and consent is not granted, drops incoming consent checks silently
	 * (testing passive 30-second expiration) instead of sending {@code 403 Forbidden}.
	 */
	public void setSilentWhenRevoked(boolean silent) {
		this.silentWhenRevoked.set(silent);
	}

	public long getRequestsHandled() {
		return requestsHandled.get();
	}

	public long getRevocationsSent() {
		return revocationsSent.get();
	}

	public InetSocketAddress getLocalAddress() {
		if (socket == null) {
			return null;
		}
		return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
	}

	/**
	 * Processes a single incoming STUN consent {@code BindingRequest} and produces the
	 * signed wire response, or {@code null} if the packet should be ignored.
	 */
	public byte[] handleRequest(byte[] rawRequest, InetSocketAddress sender) {
		if (rawRequest == null || sender == null || !ConsentSession.isStunPacket(rawRequest, rawRequest.length)) {
			return null;
		}
		try {
			MessageHeader req = MessageHeader.parseHeader(rawRequest);
			if (req.getType() != MessageHeaderType.BindingRequest) {
				return null;
			}
			req.parseAttributes(rawRequest);
			if (!req.hasMagicCookie()) {
				return null;
			}
			if (req.getMessageAttribute(MessageAttributeType.Fingerprint) != null
					&& !Fingerprint.verify(rawRequest)) {
				LOGGER.debug("Dropping STUN consent request with invalid FINGERPRINT from {}.", sender);
				return null;
			}
			Username uname = (Username) req.getMessageAttribute(MessageAttributeType.Username);
			if (expectedUsername != null && (uname == null || !expectedUsername.equals(uname.getUsername()))) {
				LOGGER.debug("Dropping STUN consent request with unexpected USERNAME from {}.", sender);
				return null;
			}
			if (!MessageHeader.verifyShortTermMessageIntegrity(rawRequest, password)) {
				LOGGER.debug("Dropping unauthenticated STUN consent request from {}.", sender);
				return null;
			}

			requestsHandled.incrementAndGet();
			if (!consentGranted.get()) {
				if (silentWhenRevoked.get()) {
					return null;
				}
				MessageHeader err = new MessageHeader(MessageHeaderType.BindingErrorResponse);
				err.setTransactionID(req.getTransactionID());
				ErrorCode ec = new ErrorCode();
				ec.setResponseCode(403);
				err.addMessageAttribute(ec);
				err.addMessageAttribute(Software.jstun());
				revocationsSent.incrementAndGet();
				return err.getBytesWithShortTermMessageIntegrityAndFingerprint(password);
			}

			MessageHeader resp = new MessageHeader(MessageHeaderType.BindingResponse);
			resp.setTransactionID(req.getTransactionID());
			XorMappedAddress xma = new XorMappedAddress(req.getTransactionID());
			xma.setAddress(new Address(sender.getAddress().getAddress()));
			xma.setPort(sender.getPort());
			resp.addMessageAttribute(xma);
			resp.addMessageAttribute(Software.jstun());
			return resp.getBytesWithShortTermMessageIntegrityAndFingerprint(password);
		} catch (MessageHeaderException | MessageAttributeException | UtilityException e) {
			LOGGER.debug("Dropping invalid STUN consent request from {}: {}", sender, e.getMessage());
			return null;
		}
	}

	/**
	 * Starts the background UDP receive loop to respond automatically to consent checks.
	 */
	public synchronized void start() {
		if (socket == null) {
			throw new IllegalStateException("Cannot start responder without a DatagramSocket");
		}
		if (running) {
			return;
		}
		running = true;
		receiveThread = new Thread(this::receiveLoop, "JSTUN-ConsentResponder-" + socket.getLocalPort());
		receiveThread.setDaemon(true);
		receiveThread.start();
	}

	private void receiveLoop() {
		try {
			socket.setSoTimeout(RECEIVE_SO_TIMEOUT_MS);
		} catch (SocketException se) {
			LOGGER.debug("Could not set timeout on consent responder socket: {}", se.getMessage());
		}
		byte[] buf = new byte[RECEIVE_BUFFER_SIZE];
		while (running && !socket.isClosed()) {
			try {
				DatagramPacket pkt = new DatagramPacket(buf, buf.length);
				socket.receive(pkt);
				byte[] data = Arrays.copyOf(pkt.getData(), pkt.getLength());
				InetSocketAddress sender = new InetSocketAddress(pkt.getAddress(), pkt.getPort());
				byte[] reply = handleRequest(data, sender);
				if (reply != null) {
					socket.send(new DatagramPacket(reply, reply.length, pkt.getAddress(), pkt.getPort()));
				}
			} catch (SocketTimeoutException ignored) {
			} catch (IOException ioe) {
				if (running && !socket.isClosed()) {
					LOGGER.debug("Consent responder I/O error: {}", ioe.getMessage());
				}
			}
		}
	}

	public synchronized void stop() {
		running = false;
		if (receiveThread != null && receiveThread != Thread.currentThread()) {
			receiveThread.interrupt();
			try {
				receiveThread.join(300L);
			} catch (InterruptedException ie) {
				Thread.currentThread().interrupt();
			}
			receiveThread = null;
		}
	}

	@Override
	public void close() {
		stop();
		if (ownsSocket && socket != null && !socket.isClosed()) {
			socket.close();
		}
	}
}
