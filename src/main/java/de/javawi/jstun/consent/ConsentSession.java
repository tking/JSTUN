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
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.LongSupplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.attribute.ErrorCode;
import de.javawi.jstun.attribute.Fingerprint;
import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.attribute.Priority;
import de.javawi.jstun.attribute.Software;
import de.javawi.jstun.attribute.Username;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderException;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.util.UtilityException;

/**
 * RFC 7675 STUN Usage for Consent Freshness session bound to a single UDP 5-tuple.
 * <p>
 * Implements the full RFC 7675 consent state machine:
 * <ul>
 *   <li>Blocks application data transmission until explicit consent is obtained (§5.1).</li>
 *   <li>Sends single-transmission, short-term-authenticated STUN Binding Requests with
 *       cryptographically strong 96-bit transaction IDs that are never exposed to callers (§5.1, §8).</li>
 *   <li>Randomizes periodic check intervals uniformly within {@code [0.8, 1.2]} of the base interval
 *       (default 5 seconds, yielding 4–6 seconds) and enforces the 4-second minimum floor (§5.1).</li>
 *   <li>Expires consent after 30 seconds without a valid, authenticated, non-error STUN Binding
 *       Response from the remote peer, discarding all outstanding transactions and rejecting
 *       late responses (§5.1).</li>
 *   <li>Immediately revokes consent upon an authenticated STUN {@code 403 Forbidden} error response
 *       or an authenticated transport close event while ignoring unauthenticated revocations (§5.2).</li>
 *   <li>Forbids reuse of the same ICE credentials on the 5-tuple after consent is lost (§5.1).</li>
 *   <li>Supports DiffServ / IP traffic class markings on the socket (§6).</li>
 * </ul>
 */
public class ConsentSession implements AutoCloseable {
	private static final Logger LOGGER = LoggerFactory.getLogger(ConsentSession.class);

	/** Default consent expiration window: 30 seconds (RFC 7675 §5). */
	public static final long DEFAULT_CONSENT_EXPIRY_MS = 30_000L;

	/** Default base interval between consent checks: 5 seconds (RFC 7675 §5.1). */
	public static final long DEFAULT_CHECK_INTERVAL_MS = 5_000L;

	/** Hard lower bound on the interval between consent checks: 4 seconds (RFC 7675 §5.1). */
	public static final long MIN_CHECK_INTERVAL_MS = 4_000L;

	/** Minimum randomization multiplier (RFC 7675 §5.1). */
	public static final double MIN_JITTER_FACTOR = 0.8;

	/** Maximum randomization multiplier (RFC 7675 §5.1). */
	public static final double MAX_JITTER_FACTOR = 1.2;

	private static final int MAX_OUTSTANDING_TRANSACTIONS = 32;
	private static final int RECEIVE_BUFFER_SIZE = 4096;
	private static final int RECEIVE_SO_TIMEOUT_MS = 100;

	private final DatagramSocket socket;
	private final boolean ownsSocket;
	private final InetSocketAddress remotePeer;
	private final String username;
	private final String password;
	private final long baseIntervalMs;
	private final long consentExpiryMs;
	private final LongSupplier clockMs;
	private final boolean enforceRfcMinInterval;
	private final SecureRandom random = new SecureRandom();

	private final Object lock = new Object();
	private final Map<String, Long> outstandingTransactions = new LinkedHashMap<String, Long>();

	private ConsentState state = ConsentState.INITIAL;
	private long lastConsentTimeMs = -1L;
	private long lastRttMs = -1L;
	private long smoothedRttMs = -1L;
	private long checksSent = 0L;
	private long responsesReceived = 0L;
	private long priority = -1L;
	private volatile ConsentListener listener;
	private volatile BiConsumer<byte[], InetSocketAddress> applicationDataHandler;

	private volatile boolean running = false;
	private ScheduledExecutorService scheduler;
	private ScheduledFuture<?> nextCheckFuture;
	private ScheduledFuture<?> expiryWatchFuture;
	private Thread receiveThread;

	/**
	 * Creates a consent session using an existing UDP socket (caller retains socket ownership)
	 * with the RFC 7675 default 5-second base interval and 30-second expiry window.
	 */
	public ConsentSession(DatagramSocket socket, InetSocketAddress remotePeer,
			String username, String password) {
		this(socket, false, remotePeer, username, password,
				DEFAULT_CHECK_INTERVAL_MS, DEFAULT_CONSENT_EXPIRY_MS,
				System::currentTimeMillis, true);
	}

	/**
	 * Creates a consent session by binding a new ephemeral UDP socket on {@code localAddress}
	 * (owned and closed by this session) with the RFC 7675 defaults (5s interval, 30s expiry).
	 */
	public ConsentSession(InetAddress localAddress, InetSocketAddress remotePeer,
			String username, String password) throws SocketException {
		this(new DatagramSocket(0, localAddress), true, remotePeer, username, password,
				DEFAULT_CHECK_INTERVAL_MS, DEFAULT_CONSENT_EXPIRY_MS,
				System::currentTimeMillis, true);
	}

	/**
	 * Creates a consent session with a custom base check interval and expiry timeout.
	 * Enforces RFC 7675 §5.1 minimum interval constraints ({@code 0.8 * baseIntervalMs >= 4000 ms}).
	 */
	public ConsentSession(DatagramSocket socket, InetSocketAddress remotePeer,
			String username, String password, long baseIntervalMs, long consentExpiryMs) {
		this(socket, false, remotePeer, username, password,
				baseIntervalMs, consentExpiryMs, System::currentTimeMillis, true);
	}

	ConsentSession(DatagramSocket socket, boolean ownsSocket, InetSocketAddress remotePeer,
			String username, String password, long baseIntervalMs, long consentExpiryMs,
			LongSupplier clockMs, boolean enforceRfcMinInterval) {
		if (socket == null) {
			throw new IllegalArgumentException("socket must not be null");
		}
		if (remotePeer == null || remotePeer.isUnresolved()) {
			throw new IllegalArgumentException("remotePeer must be a resolved InetSocketAddress");
		}
		if (username == null || username.isEmpty()) {
			throw new IllegalArgumentException("ICE short-term username must not be null or empty");
		}
		if (password == null || password.isEmpty()) {
			throw new IllegalArgumentException("ICE short-term password must not be null or empty");
		}
		if (clockMs == null) {
			throw new IllegalArgumentException("clockMs must not be null");
		}
		if (enforceRfcMinInterval) {
			if (Math.round(baseIntervalMs * MIN_JITTER_FACTOR) < MIN_CHECK_INTERVAL_MS) {
				throw new IllegalArgumentException(
						"RFC 7675 §5.1 forbids check periods below 4000 ms (baseIntervalMs must be >= 5000 ms)");
			}
			if (consentExpiryMs < MIN_CHECK_INTERVAL_MS) {
				throw new IllegalArgumentException(
						"consentExpiryMs must be at least " + MIN_CHECK_INTERVAL_MS + " ms");
			}
		} else {
			if (baseIntervalMs <= 0 || consentExpiryMs <= 0) {
				throw new IllegalArgumentException("baseIntervalMs and consentExpiryMs must be positive");
			}
		}
		this.socket = socket;
		this.ownsSocket = ownsSocket;
		this.remotePeer = remotePeer;
		this.username = username;
		this.password = password;
		this.baseIntervalMs = baseIntervalMs;
		this.consentExpiryMs = consentExpiryMs;
		this.clockMs = clockMs;
		this.enforceRfcMinInterval = enforceRfcMinInterval;
	}

	public void setListener(ConsentListener listener) {
		this.listener = listener;
	}

	/**
	 * Registers an optional callback invoked by the background receive loop when
	 * non-STUN application packets (e.g., RTP/DTLS) arrive on the same 5-tuple.
	 */
	public void setApplicationDataHandler(BiConsumer<byte[], InetSocketAddress> handler) {
		this.applicationDataHandler = handler;
	}

	/**
	 * Configures an optional ICE {@code PRIORITY} ({@code 0x0024}) value to include in
	 * outgoing consent STUN Binding Requests. Pass {@code -1} to omit the attribute.
	 */
	public void setPriority(long priority) {
		if (priority != -1L && (priority < 0L || priority > 0xFFFFFFFFL)) {
			throw new IllegalArgumentException("PRIORITY out of uint32 range: " + priority);
		}
		synchronized (lock) {
			this.priority = priority;
		}
	}

	/**
	 * Applies DiffServ / IP traffic class markings to the underlying UDP socket
	 * as recommended by RFC 7675 §6.
	 */
	public void setTrafficClass(int trafficClass) throws SocketException {
		socket.setTrafficClass(trafficClass);
		LOGGER.debug("Applied traffic class 0x{} on consent socket for {}.",
				Integer.toHexString(trafficClass), remotePeer);
	}

	public InetSocketAddress getRemotePeer() {
		return remotePeer;
	}

	public InetSocketAddress getLocalAddress() {
		return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
	}

	public long getBaseIntervalMs() {
		return baseIntervalMs;
	}

	public long getConsentExpiryMs() {
		return consentExpiryMs;
	}

	public ConsentState getState() {
		checkExpiration();
		synchronized (lock) {
			return state;
		}
	}

	public long getLastRttMs() {
		synchronized (lock) {
			return lastRttMs;
		}
	}

	public long getSmoothedRttMs() {
		synchronized (lock) {
			return smoothedRttMs;
		}
	}

	public long getChecksSent() {
		synchronized (lock) {
			return checksSent;
		}
	}

	public long getResponsesReceived() {
		synchronized (lock) {
			return responsesReceived;
		}
	}

	public int getOutstandingTransactionCount() {
		synchronized (lock) {
			return outstandingTransactions.size();
		}
	}

	/**
	 * Returns the remaining consent validity time in milliseconds, or {@code 0}
	 * if consent is not currently {@link ConsentState#ACTIVE}.
	 */
	public long getRemainingConsentMs() {
		checkExpiration();
		synchronized (lock) {
			if (state != ConsentState.ACTIVE || lastConsentTimeMs < 0L) {
				return 0L;
			}
			long elapsed = Math.max(0L, clockMs.getAsLong() - lastConsentTimeMs);
			return Math.max(0L, consentExpiryMs - elapsed);
		}
	}

	/**
	 * Marks initial consent as obtained when an external ICE state machine transitions
	 * this candidate pair to the {@code Succeeded} state (RFC 7675 §5).
	 */
	public void markInitialConsentObtained() {
		ConsentListener cb = null;
		synchronized (lock) {
			if (state == ConsentState.EXPIRED || state == ConsentState.REVOKED) {
				throw new IllegalStateException(
						"Consent already lost (" + state + "); ICE restart with new credentials is required (RFC 7675 §5.1)");
			}
			long now = clockMs.getAsLong();
			lastConsentTimeMs = now;
			if (state == ConsentState.INITIAL) {
				state = ConsentState.ACTIVE;
				cb = listener;
				LOGGER.info("Initial ICE consent marked ACTIVE for {}.", remotePeer);
			}
		}
		if (cb != null) {
			cb.onConsentObtained(this);
		}
	}

	/**
	 * Returns {@code true} if and only if peer consent is currently fresh ({@link ConsentState#ACTIVE})
	 * and application data is permitted on this 5-tuple (RFC 7675 §5.1).
	 */
	public boolean canSendApplicationData() {
		return getState() == ConsentState.ACTIVE;
	}

	/**
	 * Transmits application data on this 5-tuple only if peer consent is currently active.
	 *
	 * @throws IllegalStateException if consent has not been obtained or has expired/been revoked
	 */
	public void sendApplicationData(byte[] payload) throws IOException {
		if (payload == null) {
			throw new IllegalArgumentException("payload must not be null");
		}
		if (!canSendApplicationData()) {
			throw new IllegalStateException(
					"Cannot send application data without active RFC 7675 consent (state=" + getState() + ")");
		}
		DatagramPacket pkt = new DatagramPacket(payload, payload.length,
				remotePeer.getAddress(), remotePeer.getPort());
		socket.send(pkt);
	}

	/**
	 * Computes the next randomized check interval uniformly in
	 * {@code [0.8 * baseIntervalMs, 1.2 * baseIntervalMs]} (RFC 7675 §5.1).
	 */
	public long nextRandomizedIntervalMs() {
		double factor = MIN_JITTER_FACTOR + ((MAX_JITTER_FACTOR - MIN_JITTER_FACTOR) * random.nextDouble());
		long interval = Math.round(baseIntervalMs * factor);
		if (enforceRfcMinInterval && interval < MIN_CHECK_INTERVAL_MS) {
			interval = MIN_CHECK_INTERVAL_MS;
		}
		return Math.max(1L, interval);
	}

	/**
	 * Builds and transmits a single RFC 7675 STUN Binding Request for consent freshness
	 * with a fresh, unexposed 96-bit random Transaction ID, {@code USERNAME}, optional
	 * {@code PRIORITY}, short-term {@code MESSAGE-INTEGRITY}, and {@code FINGERPRINT}.
	 * <p>
	 * Per RFC 7675 §5.1, each consent request is transmitted once only (no STUN retransmission).
	 */
	public void sendConsentCheck() throws IOException, UtilityException {
		checkExpiration();
		byte[] wire;
		synchronized (lock) {
			if (state == ConsentState.EXPIRED || state == ConsentState.REVOKED) {
				throw new IllegalStateException(
						"Consent lost (" + state + "); ICE restart with new credentials is required (RFC 7675 §5.1)");
			}
			MessageHeader req = new MessageHeader(MessageHeaderType.BindingRequest);
			req.generateTransactionID();
			req.addMessageAttribute(new Username(username));
			if (priority >= 0L) {
				try {
					req.addMessageAttribute(new Priority(priority));
				} catch (MessageAttributeException e) {
					throw new UtilityException("Invalid PRIORITY value: " + e.getMessage());
				}
			}
			req.addMessageAttribute(Software.jstun());
			wire = req.getBytesWithShortTermMessageIntegrityAndFingerprint(password);

			String txKey = txKey(req.getTransactionID());
			if (outstandingTransactions.size() >= MAX_OUTSTANDING_TRANSACTIONS) {
				Iterator<String> oldest = outstandingTransactions.keySet().iterator();
				if (oldest.hasNext()) {
					oldest.next();
					oldest.remove();
				}
			}
			outstandingTransactions.put(txKey, clockMs.getAsLong());
			checksSent++;
		}

		DatagramPacket pkt = new DatagramPacket(wire, wire.length,
				remotePeer.getAddress(), remotePeer.getPort());
		socket.send(pkt);
		LOGGER.debug("Sent RFC 7675 STUN consent check #{} to {}.", getChecksSent(), remotePeer);
	}

	/**
	 * Processes an incoming UDP packet received on this 5-tuple.
	 *
	 * @param rawPacket the exact received bytes
	 * @param sender    the remote source transport address
	 * @return {@code true} if the packet was a valid, authenticated STUN consent response
	 *         matching an outstanding transaction; {@code false} if ignored or non-STUN
	 */
	public boolean processIncomingPacket(byte[] rawPacket, InetSocketAddress sender) {
		checkExpiration();
		if (rawPacket == null || rawPacket.length < 20 || sender == null) {
			return false;
		}
		if (!remotePeer.equals(sender)) {
			LOGGER.debug("Ignoring packet from unexpected peer {} (expected {}).", sender, remotePeer);
			return false;
		}
		if (!isStunPacket(rawPacket, rawPacket.length)) {
			return false;
		}

		synchronized (lock) {
			if (state == ConsentState.EXPIRED || state == ConsentState.REVOKED) {
				// RFC 7675 §5.1: STUN consent responses received after consent expiry
				// do not re-establish consent and must be discarded.
				LOGGER.debug("Discarding late STUN consent response after consent loss (state={}).", state);
				return false;
			}
		}

		MessageHeader mh;
		try {
			mh = MessageHeader.parseHeader(rawPacket);
			MessageHeaderType type = mh.getType();
			if (type != MessageHeaderType.BindingResponse && type != MessageHeaderType.BindingErrorResponse) {
				return false;
			}
			mh.parseAttributes(rawPacket);
			if (!mh.hasMagicCookie()) {
				return false;
			}
			if (mh.getMessageAttribute(MessageAttributeType.Fingerprint) != null
					&& !Fingerprint.verify(rawPacket)) {
				LOGGER.debug("Ignoring STUN consent response with invalid FINGERPRINT from {}.", sender);
				return false;
			}
		} catch (MessageHeaderException | MessageAttributeException e) {
			LOGGER.debug("Ignoring malformed STUN packet from {}: {}", sender, e.getMessage());
			return false;
		}

		String key = txKey(mh.getTransactionID());
		boolean isOutstanding;
		synchronized (lock) {
			isOutstanding = outstandingTransactions.containsKey(key);
		}
		if (!isOutstanding) {
			LOGGER.debug("Ignoring STUN response with unknown or already-completed transaction ID from {}.", sender);
			return false;
		}

		// Verify short-term MESSAGE-INTEGRITY before mutating transaction or consent state
		try {
			if (!MessageHeader.verifyShortTermMessageIntegrity(rawPacket, password)) {
				LOGGER.warn("Ignoring unauthenticated STUN response (invalid MESSAGE-INTEGRITY) from {}.", sender);
				return false;
			}
		} catch (UtilityException | MessageAttributeException e) {
			LOGGER.warn("Failed to verify MESSAGE-INTEGRITY on STUN response from {}: {}", sender, e.getMessage());
			return false;
		}

		long now = clockMs.getAsLong();
		ConsentListener cb = null;
		boolean becameActive = false;
		boolean refreshed = false;
		boolean revoked = false;
		String revokeReason = null;
		long rttMs = 0L;

		synchronized (lock) {
			if (state == ConsentState.EXPIRED || state == ConsentState.REVOKED) {
				return false;
			}
			Long sentAt = outstandingTransactions.remove(key);
			if (sentAt == null) {
				return false;
			}

			if (mh.getType() == MessageHeaderType.BindingResponse) {
				rttMs = Math.max(0L, now - sentAt);
				lastRttMs = rttMs;
				smoothedRttMs = (smoothedRttMs < 0L) ? rttMs : ((7L * smoothedRttMs + rttMs) / 8L);
				lastConsentTimeMs = now;
				responsesReceived++;
				if (state == ConsentState.INITIAL) {
					state = ConsentState.ACTIVE;
					becameActive = true;
				}
				refreshed = true;
				cb = listener;
			} else {
				ErrorCode ec = (ErrorCode) mh.getMessageAttribute(MessageAttributeType.ErrorCode);
				if (ec != null && ec.getResponseCode() == 403) {
					// RFC 7675 §5.2: Valid and authenticated 403 Forbidden immediately revokes consent
					state = ConsentState.REVOKED;
					outstandingTransactions.clear();
					revoked = true;
					revokeReason = "STUN 403 " + ec.getReason();
					cb = listener;
					LOGGER.info("Consent immediately REVOKED for {} via authenticated STUN 403 Forbidden.", remotePeer);
				} else {
					LOGGER.debug("Received authenticated non-403 STUN error (code={}) from {}; consent not refreshed.",
							ec != null ? ec.getResponseCode() : -1, remotePeer);
				}
			}
		}

		if (revoked) {
			stopBackgroundWorkers();
			if (cb != null) {
				cb.onConsentRevoked(this, revokeReason);
			}
		} else if (refreshed) {
			LOGGER.debug("Consent refreshed for {} (RTT={} ms, smoothed={} ms).", remotePeer, rttMs, getSmoothedRttMs());
			if (cb != null) {
				if (becameActive) {
					cb.onConsentObtained(this);
				}
				cb.onConsentRefreshed(this, rttMs);
			}
		}
		return true;
	}

	/**
	 * Checks whether the 30-second consent expiration window has elapsed and, if so,
	 * transitions to {@link ConsentState#EXPIRED} and discards all outstanding
	 * STUN consent transactions (RFC 7675 §5.1).
	 *
	 * @return {@code true} if consent is now {@link ConsentState#EXPIRED}
	 */
	public boolean checkExpiration() {
		ConsentListener cb = null;
		boolean newlyExpired = false;
		synchronized (lock) {
			if (state == ConsentState.ACTIVE && lastConsentTimeMs >= 0L) {
				long elapsed = clockMs.getAsLong() - lastConsentTimeMs;
				if (elapsed >= consentExpiryMs) {
					state = ConsentState.EXPIRED;
					outstandingTransactions.clear();
					newlyExpired = true;
					cb = listener;
					LOGGER.info("Consent EXPIRED for {} after {} ms without valid STUN response.",
							remotePeer, elapsed);
				}
			}
		}
		if (newlyExpired) {
			stopBackgroundWorkers();
			if (cb != null) {
				cb.onConsentExpired(this);
			}
		}
		synchronized (lock) {
			return state == ConsentState.EXPIRED;
		}
	}

	/**
	 * Immediately revokes consent upon receipt of an authenticated close message
	 * (such as a DTLS/TLS fatal alert), discarding all outstanding STUN transactions
	 * (RFC 7675 §5.2).
	 */
	public void revokeByAuthenticatedClose(String reason) {
		ConsentListener cb = null;
		boolean newlyRevoked = false;
		String finalReason = (reason != null && !reason.isEmpty()) ? reason : "Authenticated transport closure";
		synchronized (lock) {
			if (state != ConsentState.REVOKED && state != ConsentState.EXPIRED) {
				state = ConsentState.REVOKED;
				outstandingTransactions.clear();
				newlyRevoked = true;
				cb = listener;
				LOGGER.info("Consent immediately REVOKED for {}: {}", remotePeer, finalReason);
			}
		}
		if (newlyRevoked) {
			stopBackgroundWorkers();
			if (cb != null) {
				cb.onConsentRevoked(this, finalReason);
			}
		}
	}

	/**
	 * Records an unauthenticated close indication (such as a TCP FIN or unauthenticated
	 * reset). Per RFC 7675 §5.2, unauthenticated close messages MUST NOT revoke consent;
	 * consent continues until it expires or is revoked by an authenticated signal.
	 */
	public void onUnauthenticatedClose(String reason) {
		LOGGER.debug("Ignoring unauthenticated close signal for {} (RFC 7675 §5.2): {}", remotePeer, reason);
	}

	/**
	 * Creates a fresh {@link ConsentSession} on the same 5-tuple after an ICE restart
	 * with new credentials, enforcing RFC 7675 §5.1's requirement that identical ICE
	 * credentials MUST NOT be reused after consent is lost.
	 */
	public ConsentSession restartWithNewCredentials(String newUsername, String newPassword) {
		if (newUsername == null || newUsername.isEmpty() || newPassword == null || newPassword.isEmpty()) {
			throw new IllegalArgumentException("New ICE credentials must not be null or empty");
		}
		if (username.equals(newUsername) && password.equals(newPassword)) {
			throw new IllegalArgumentException(
					"RFC 7675 §5.1 forbids reusing the same ICE credentials on a 5-tuple after consent loss");
		}
		stopBackgroundWorkers();
		ConsentSession restarted = new ConsentSession(
				socket, false, remotePeer, newUsername, newPassword,
				baseIntervalMs, consentExpiryMs, clockMs, enforceRfcMinInterval);
		restarted.setListener(listener);
		restarted.setApplicationDataHandler(applicationDataHandler);
		synchronized (lock) {
			if (priority >= 0L) {
				restarted.setPriority(priority);
			}
		}
		return restarted;
	}

	/**
	 * Starts the background receive loop and randomized periodic RFC 7675 consent
	 * check scheduler, immediately sending the first consent check.
	 */
	public void start() {
		synchronized (lock) {
			if (state == ConsentState.EXPIRED || state == ConsentState.REVOKED) {
				throw new IllegalStateException(
						"Consent lost (" + state + "); ICE restart with new credentials is required (RFC 7675 §5.1)");
			}
			if (running) {
				return;
			}
			running = true;
			scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
				Thread t = new Thread(r, "JSTUN-ConsentTimer-" + remotePeer.getPort());
				t.setDaemon(true);
				return t;
			});
			receiveThread = new Thread(this::receiveLoop, "JSTUN-ConsentRecv-" + remotePeer.getPort());
			receiveThread.setDaemon(true);
			receiveThread.start();

			long watchPeriod = Math.max(25L, Math.min(1000L, consentExpiryMs / 4L));
			expiryWatchFuture = scheduler.scheduleAtFixedRate(
					this::checkExpiration, watchPeriod, watchPeriod, TimeUnit.MILLISECONDS);
			scheduleNextCheck(0L);
		}
	}

	private void scheduleNextCheck(long delayMs) {
		synchronized (lock) {
			if (!running || scheduler == null || scheduler.isShutdown()) {
				return;
			}
			nextCheckFuture = scheduler.schedule(() -> {
				if (!running) {
					return;
				}
				if (checkExpiration()) {
					return;
				}
				try {
					sendConsentCheck();
				} catch (IllegalStateException ise) {
					return;
				} catch (Exception e) {
					LOGGER.debug("Error sending scheduled consent check to {}: {}", remotePeer, e.getMessage());
				}
				scheduleNextCheck(nextRandomizedIntervalMs());
			}, delayMs, TimeUnit.MILLISECONDS);
		}
	}

	private void receiveLoop() {
		try {
			socket.setSoTimeout(RECEIVE_SO_TIMEOUT_MS);
		} catch (SocketException se) {
			LOGGER.debug("Could not configure receive timeout on consent socket: {}", se.getMessage());
		}
		byte[] buf = new byte[RECEIVE_BUFFER_SIZE];
		while (running && !socket.isClosed()) {
			try {
				DatagramPacket pkt = new DatagramPacket(buf, buf.length);
				socket.receive(pkt);
				byte[] data = Arrays.copyOf(pkt.getData(), pkt.getLength());
				InetSocketAddress sender = new InetSocketAddress(pkt.getAddress(), pkt.getPort());
				if (isStunPacket(data, data.length)) {
					processIncomingPacket(data, sender);
				} else {
					BiConsumer<byte[], InetSocketAddress> appHandler = applicationDataHandler;
					if (appHandler != null) {
						appHandler.accept(data, sender);
					}
				}
			} catch (SocketTimeoutException ignored) {
				checkExpiration();
			} catch (IOException ioe) {
				if (running && !socket.isClosed()) {
					LOGGER.debug("Receive error on consent socket: {}", ioe.getMessage());
				}
			}
		}
	}

	private void stopBackgroundWorkers() {
		running = false;
		ScheduledExecutorService exec;
		Thread rx;
		synchronized (lock) {
			if (nextCheckFuture != null) {
				nextCheckFuture.cancel(false);
				nextCheckFuture = null;
			}
			if (expiryWatchFuture != null) {
				expiryWatchFuture.cancel(false);
				expiryWatchFuture = null;
			}
			exec = scheduler;
			scheduler = null;
			rx = receiveThread;
			receiveThread = null;
		}
		if (exec != null) {
			exec.shutdownNow();
		}
		if (rx != null && rx != Thread.currentThread()) {
			rx.interrupt();
			try {
				rx.join(300L);
			} catch (InterruptedException ie) {
				Thread.currentThread().interrupt();
			}
		}
	}

	/**
	 * Stops background timers and receiver threads without closing a caller-owned socket.
	 */
	public void stop() {
		stopBackgroundWorkers();
	}

	@Override
	public void close() {
		stopBackgroundWorkers();
		if (ownsSocket && !socket.isClosed()) {
			socket.close();
		}
	}

	/**
	 * Identifies RFC 5389/7983 STUN packets on a multiplexed UDP 5-tuple by checking
	 * length, leading zero bits, and the 32-bit STUN Magic Cookie ({@code 0x2112A442}).
	 */
	public static boolean isStunPacket(byte[] data, int length) {
		if (data == null || length < 20 || data.length < length) {
			return false;
		}
		return (data[0] & 0xC0) == 0
				&& data[4] == 0x21
				&& data[5] == 0x12
				&& data[6] == (byte) 0xA4
				&& data[7] == 0x42;
	}

	private static String txKey(byte[] transactionId) {
		StringBuilder sb = new StringBuilder(transactionId.length * 2);
		for (byte b : transactionId) {
			sb.append(Character.forDigit((b >>> 4) & 0x0F, 16));
			sb.append(Character.forDigit(b & 0x0F, 16));
		}
		return sb.toString();
	}
}
