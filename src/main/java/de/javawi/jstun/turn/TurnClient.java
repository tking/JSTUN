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

package de.javawi.jstun.turn;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.attribute.ChannelNumber;
import de.javawi.jstun.attribute.Data;
import de.javawi.jstun.attribute.ErrorCode;
import de.javawi.jstun.attribute.EvenPort;
import de.javawi.jstun.attribute.Fingerprint;
import de.javawi.jstun.attribute.Lifetime;
import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.attribute.Nonce;
import de.javawi.jstun.attribute.Realm;
import de.javawi.jstun.attribute.RequestedTransport;
import de.javawi.jstun.attribute.ReservationToken;
import de.javawi.jstun.attribute.Software;
import de.javawi.jstun.attribute.Username;
import de.javawi.jstun.attribute.XorMappedAddress;
import de.javawi.jstun.attribute.XorPeerAddress;
import de.javawi.jstun.attribute.XorRelayedAddress;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.util.Address;
import de.javawi.jstun.util.UtilityException;

/**
 * RFC 5766 (TURN) UDP client supporting long-term credential authentication
 * (automatic {@code 401} challenge and {@code 438} stale-nonce retry),
 * {@code Allocate}, {@code Refresh}, {@code CreatePermission}, {@code ChannelBind},
 * {@code Send}/{@code Data} indications, and binary {@code ChannelData} relaying.
 */
public class TurnClient implements AutoCloseable {
	private static final Logger LOGGER = LoggerFactory.getLogger(TurnClient.class);
	private static final int RECEIVE_BUFFER_SIZE = 10240;

	public static final class ReceivedTurnData {
		private final InetSocketAddress peer;
		private final byte[] data;
		private final boolean viaChannel;
		private final int channelNumber;

		public ReceivedTurnData(InetSocketAddress peer, byte[] data, boolean viaChannel, int channelNumber) {
			this.peer = peer;
			this.data = Arrays.copyOf(data, data.length);
			this.viaChannel = viaChannel;
			this.channelNumber = channelNumber;
		}

		public InetSocketAddress getPeer() {
			return peer;
		}

		public byte[] getData() {
			return Arrays.copyOf(data, data.length);
		}

		public boolean isViaChannel() {
			return viaChannel;
		}

		public int getChannelNumber() {
			return channelNumber;
		}
	}

	private final InetAddress localAddress;
	private final int localPort;
	private final String turnServerHost;
	private final int turnServerPort;
	private final String username;
	private final String password;

	private int timeoutInitValueMs = 300;
	private int maxWaitTimeMs = 2400;

	private DatagramSocket socket;
	private InetAddress resolvedServerIp;
	private Thread receiverThread;
	private volatile boolean running;

	private volatile String realm;
	private volatile String nonce;
	private volatile InetSocketAddress relayedAddress;
	private volatile InetSocketAddress mappedAddress;
	private volatile long lifetimeSeconds;
	private volatile ReservationToken reservationToken;

	private final Map<ByteBuffer, CompletableFuture<MessageHeader>> pendingRequests =
			new ConcurrentHashMap<ByteBuffer, CompletableFuture<MessageHeader>>();
	private final Map<Integer, InetSocketAddress> channelsByNumber =
			new ConcurrentHashMap<Integer, InetSocketAddress>();
	private final BlockingQueue<ReceivedTurnData> inboundQueue = new LinkedBlockingQueue<ReceivedTurnData>();
	private volatile Consumer<ReceivedTurnData> dataListener;

	public TurnClient(InetAddress localAddress, String turnServerHost, int turnServerPort,
			String username, String password) {
		this(localAddress, 0, turnServerHost, turnServerPort, username, password);
	}

	public TurnClient(InetAddress localAddress, int localPort, String turnServerHost, int turnServerPort,
			String username, String password) {
		this.localAddress = localAddress;
		this.localPort = localPort;
		this.turnServerHost = turnServerHost;
		this.turnServerPort = turnServerPort;
		this.username = username;
		this.password = password;
	}

	public void setTimeoutInitValueMs(int timeoutInitValueMs) {
		this.timeoutInitValueMs = Math.max(10, timeoutInitValueMs);
	}

	public void setMaxWaitTimeMs(int maxWaitTimeMs) {
		this.maxWaitTimeMs = Math.max(20, maxWaitTimeMs);
	}

	public void setDataListener(Consumer<ReceivedTurnData> dataListener) {
		this.dataListener = dataListener;
	}

	public InetSocketAddress getRelayedAddress() {
		return relayedAddress;
	}

	public InetSocketAddress getMappedAddress() {
		return mappedAddress;
	}

	public long getLifetimeSeconds() {
		return lifetimeSeconds;
	}

	public ReservationToken getReservationToken() {
		return reservationToken;
	}

	public String getRealm() {
		return realm;
	}

	public String getNonce() {
		return nonce;
	}

	private synchronized void ensureStarted() throws IOException {
		if (running && socket != null && !socket.isClosed()) {
			return;
		}
		this.resolvedServerIp = resolveServerAddress(turnServerHost, localAddress);
		this.socket = new DatagramSocket(new InetSocketAddress(localAddress, localPort));
		this.socket.setReceiveBufferSize(65536);
		this.socket.setSendBufferSize(65536);
		this.running = true;
		this.receiverThread = new Thread(this::receiveLoop, "turn-client-recv-" + socket.getLocalPort());
		this.receiverThread.setDaemon(true);
		this.receiverThread.start();
	}

	private static InetAddress resolveServerAddress(String host, InetAddress sourceAddress) throws UnknownHostException {
		InetAddress[] candidates = InetAddress.getAllByName(host);
		if (sourceAddress == null || sourceAddress.isAnyLocalAddress()) {
			return candidates[0];
		}
		boolean wantV6 = sourceAddress instanceof Inet6Address;
		for (InetAddress candidate : candidates) {
			if (wantV6 == (candidate instanceof Inet6Address)) {
				return candidate;
			}
		}
		throw new UnknownHostException("No " + (wantV6 ? "IPv6" : "IPv4") + " address found for TURN server: " + host);
	}

	public InetSocketAddress allocate() throws TurnException, IOException {
		return allocate(TurnServer.DEFAULT_LIFETIME_SECONDS, false, false);
	}

	public InetSocketAddress allocate(long requestedLifetimeSeconds, boolean evenPort, boolean reserveNextPort)
			throws TurnException, IOException {
		ensureStarted();
		MessageHeader resp = sendAuthenticatedRequest(MessageHeaderType.AllocateRequest, req -> {
			req.addMessageAttribute(new RequestedTransport(RequestedTransport.PROTOCOL_UDP));
			if (requestedLifetimeSeconds > 0) {
				req.addMessageAttribute(new Lifetime(requestedLifetimeSeconds));
			}
			if (evenPort) {
				req.addMessageAttribute(new EvenPort(reserveNextPort));
			}
		});
		return parseAllocateResponse(resp);
	}

	public InetSocketAddress allocateWithReservationToken(ReservationToken token, long requestedLifetimeSeconds)
			throws TurnException, IOException {
		if (token == null) {
			throw new IllegalArgumentException("ReservationToken must not be null");
		}
		ensureStarted();
		MessageHeader resp = sendAuthenticatedRequest(MessageHeaderType.AllocateRequest, req -> {
			req.addMessageAttribute(new RequestedTransport(RequestedTransport.PROTOCOL_UDP));
			if (requestedLifetimeSeconds > 0) {
				req.addMessageAttribute(new Lifetime(requestedLifetimeSeconds));
			}
			req.addMessageAttribute(token);
		});
		return parseAllocateResponse(resp);
	}

	private InetSocketAddress parseAllocateResponse(MessageHeader resp) throws TurnException {
		try {
			XorRelayedAddress xra = (XorRelayedAddress) resp.getMessageAttribute(MessageAttributeType.XorRelayedAddress);
			if (xra == null) {
				throw new TurnException("AllocateResponse missing XOR-RELAYED-ADDRESS");
			}
			this.relayedAddress = new InetSocketAddress(xra.getAddress().getInetAddress(), xra.getPort());
			XorMappedAddress xma = (XorMappedAddress) resp.getMessageAttribute(MessageAttributeType.XorMappedAddress);
			if (xma != null) {
				this.mappedAddress = new InetSocketAddress(xma.getAddress().getInetAddress(), xma.getPort());
			}
			Lifetime lt = (Lifetime) resp.getMessageAttribute(MessageAttributeType.Lifetime);
			if (lt != null) {
				this.lifetimeSeconds = lt.getLifetime();
			}
			this.reservationToken = (ReservationToken) resp.getMessageAttribute(MessageAttributeType.ReservationToken);
			LOGGER.info("TURN allocation established: relayed={}, mapped={}, lifetime={}s.",
					relayedAddress, mappedAddress, lifetimeSeconds);
			return relayedAddress;
		} catch (UtilityException | UnknownHostException e) {
			throw new TurnException("Failed to parse AllocateResponse: " + e.getMessage(), e);
		}
	}

	public long refresh(long requestedLifetimeSeconds) throws TurnException, IOException {
		ensureStarted();
		MessageHeader resp = sendAuthenticatedRequest(MessageHeaderType.RefreshRequest, req -> {
			req.addMessageAttribute(new Lifetime(requestedLifetimeSeconds));
		});
		Lifetime lt = (Lifetime) resp.getMessageAttribute(MessageAttributeType.Lifetime);
		this.lifetimeSeconds = (lt != null) ? lt.getLifetime() : 0L;
		if (this.lifetimeSeconds == 0L) {
			this.relayedAddress = null;
			this.channelsByNumber.clear();
		}
		return this.lifetimeSeconds;
	}

	public void createPermission(InetAddress... peerAddresses) throws TurnException, IOException {
		if (peerAddresses == null || peerAddresses.length == 0) {
			throw new IllegalArgumentException("At least one peer address is required");
		}
		ensureStarted();
		sendAuthenticatedRequest(MessageHeaderType.CreatePermissionRequest, req -> {
			for (InetAddress peerIp : peerAddresses) {
				XorPeerAddress xpa = new XorPeerAddress();
				xpa.setAddress(new Address(peerIp.getAddress()));
				xpa.setPort(0);
				req.addMessageAttribute(xpa);
			}
		});
	}

	public void channelBind(int channelNumber, InetSocketAddress peer) throws TurnException, IOException {
		if (peer == null || peer.getAddress() == null || peer.getPort() <= 0) {
			throw new IllegalArgumentException("Valid peer InetSocketAddress is required");
		}
		ensureStarted();
		sendAuthenticatedRequest(MessageHeaderType.ChannelBindRequest, req -> {
			req.addMessageAttribute(new ChannelNumber(channelNumber));
			XorPeerAddress xpa = new XorPeerAddress();
			xpa.setAddress(new Address(peer.getAddress().getAddress()));
			xpa.setPort(peer.getPort());
			req.addMessageAttribute(xpa);
		});
		channelsByNumber.put(channelNumber, peer);
	}

	public void sendDataIndication(InetSocketAddress peer, byte[] payload) throws TurnException, IOException {
		if (peer == null || peer.getAddress() == null || peer.getPort() <= 0) {
			throw new IllegalArgumentException("Valid peer InetSocketAddress is required");
		}
		ensureStarted();
		try {
			MessageHeader ind = new MessageHeader(MessageHeaderType.SendIndication);
			ind.generateTransactionID();
			XorPeerAddress xpa = new XorPeerAddress(ind.getTransactionID());
			xpa.setAddress(new Address(peer.getAddress().getAddress()));
			xpa.setPort(peer.getPort());
			ind.addMessageAttribute(xpa);
			ind.addMessageAttribute(new Data(payload));
			byte[] bytes = ind.getBytesWithFingerprint();
			socket.send(new DatagramPacket(bytes, bytes.length, resolvedServerIp, turnServerPort));
		} catch (UtilityException | MessageAttributeException e) {
			throw new TurnException("Failed to build SendIndication: " + e.getMessage(), e);
		}
	}

	public void sendChannelData(int channelNumber, byte[] payload) throws TurnException, IOException {
		ensureStarted();
		try {
			ChannelData cd = new ChannelData(channelNumber, payload);
			byte[] bytes = cd.getBytes();
			socket.send(new DatagramPacket(bytes, bytes.length, resolvedServerIp, turnServerPort));
		} catch (MessageAttributeException e) {
			throw new TurnException("Failed to build ChannelData: " + e.getMessage(), e);
		}
	}

	public ReceivedTurnData receiveData(long timeoutMs) throws InterruptedException {
		return inboundQueue.poll(timeoutMs, TimeUnit.MILLISECONDS);
	}

	@FunctionalInterface
	private interface RequestPopulator {
		void populate(MessageHeader req) throws UtilityException, MessageAttributeException;
	}

	private MessageHeader sendAuthenticatedRequest(MessageHeaderType type, RequestPopulator populator)
			throws TurnException, IOException {
		for (int authAttempt = 0; authAttempt < 3; authAttempt++) {
			MessageHeader req = new MessageHeader(type);
			byte[] wireBytes;
			try {
				req.generateTransactionID();
				populator.populate(req);
				req.addMessageAttribute(Software.jstun());
				if (realm != null && nonce != null) {
					req.addMessageAttribute(new Username(username));
					req.addMessageAttribute(new Realm(realm));
					req.addMessageAttribute(new Nonce(nonce));
					wireBytes = req.getBytesWithLongTermMessageIntegrityAndFingerprint(username, realm, password);
				} else {
					wireBytes = req.getBytesWithFingerprint();
				}
			} catch (UtilityException | MessageAttributeException e) {
				throw new TurnException("Failed to serialize TURN request: " + e.getMessage(), e);
			}

			MessageHeader resp = sendAndAwaitResponse(req.getTransactionID(), wireBytes);
			ErrorCode ec = (ErrorCode) resp.getMessageAttribute(MessageAttributeType.ErrorCode);
			if (ec == null) {
				return resp;
			}
			int code = ec.getResponseCode();
			if ((code == 401 || code == 438) && authAttempt < 2) {
				Realm r = (Realm) resp.getMessageAttribute(MessageAttributeType.Realm);
				Nonce n = (Nonce) resp.getMessageAttribute(MessageAttributeType.Nonce);
				if (r != null && n != null && !n.getNonce().isEmpty()) {
					boolean hadCredentials = (this.realm != null && this.nonce != null);
					this.realm = r.getRealm();
					this.nonce = n.getNonce();
					// On 401 when credentials were already sent, do not loop if password is wrong
					if (code == 401 && hadCredentials) {
						throw new TurnException(code, ec.getReason());
					}
					LOGGER.debug("TURN {} challenge received (realm='{}'); retrying authenticated request.", code, this.realm);
					continue;
				}
			}
			throw new TurnException(code, ec.getReason());
		}
		throw new TurnException("TURN authentication failed after retries");
	}

	private MessageHeader sendAndAwaitResponse(byte[] txId, byte[] wireBytes) throws TurnException, IOException {
		ByteBuffer key = ByteBuffer.wrap(Arrays.copyOf(txId, txId.length));
		CompletableFuture<MessageHeader> future = new CompletableFuture<MessageHeader>();
		pendingRequests.put(key, future);
		try {
			int elapsed = 0;
			int timeout = timeoutInitValueMs;
			while (true) {
				socket.send(new DatagramPacket(wireBytes, wireBytes.length, resolvedServerIp, turnServerPort));
				try {
					return future.get(timeout, TimeUnit.MILLISECONDS);
				} catch (TimeoutException te) {
					if (elapsed < maxWaitTimeMs) {
						elapsed += timeout;
						timeout = Math.min(timeout * 2, 1600);
					} else {
						throw new TurnException("TURN request timed out after " + elapsed + " ms");
					}
				} catch (InterruptedException ie) {
					Thread.currentThread().interrupt();
					throw new TurnException("Interrupted waiting for TURN response", ie);
				} catch (ExecutionException ee) {
					throw new TurnException("Error receiving TURN response: " + ee.getMessage(), ee);
				}
			}
		} finally {
			pendingRequests.remove(key);
		}
	}

	private void receiveLoop() {
		byte[] buf = new byte[RECEIVE_BUFFER_SIZE];
		DatagramPacket pkt = new DatagramPacket(buf, buf.length);
		while (running && socket != null && !socket.isClosed()) {
			try {
				pkt.setData(buf, 0, buf.length);
				socket.receive(pkt);
				byte[] data = Arrays.copyOf(buf, pkt.getLength());
				if (ChannelData.isChannelData(data)) {
					ChannelData cd = ChannelData.parse(data);
					InetSocketAddress peer = channelsByNumber.get(cd.getChannelNumber());
					if (peer != null) {
						deliverInboundData(new ReceivedTurnData(peer, cd.getData(), true, cd.getChannelNumber()));
					}
					continue;
				}
				MessageHeader msg = MessageHeader.parseHeader(data);
				msg.parseAttributes(data);
				if (msg.getMessageAttribute(MessageAttributeType.Fingerprint) != null && !Fingerprint.verify(data)) {
					LOGGER.warn("TurnClient discarding packet with invalid FINGERPRINT.");
					continue;
				}
				if (msg.getType() == MessageHeaderType.DataIndication) {
					XorPeerAddress xpa = (XorPeerAddress) msg.getMessageAttribute(MessageAttributeType.XorPeerAddress);
					Data payload = (Data) msg.getMessageAttribute(MessageAttributeType.Data);
					if (xpa != null && payload != null) {
						InetSocketAddress peer = new InetSocketAddress(xpa.getAddress().getInetAddress(), xpa.getPort());
						deliverInboundData(new ReceivedTurnData(peer, payload.getData(), false, -1));
					}
					continue;
				}
				ByteBuffer key = ByteBuffer.wrap(msg.getTransactionID());
				CompletableFuture<MessageHeader> pending = pendingRequests.get(key);
				if (pending != null) {
					pending.complete(msg);
				}
			} catch (SocketException se) {
				if (!running || socket.isClosed()) {
					break;
				}
				LOGGER.warn("SocketException in TurnClient receiver: {}", se.getMessage());
			} catch (MessageHeaderParsingException | MessageAttributeParsingException | UtilityException
					| IOException | RuntimeException e) {
				LOGGER.debug("TurnClient discarding malformed/unhandled packet: {}", e.getMessage());
			}
		}
	}

	private void deliverInboundData(ReceivedTurnData received) {
		Consumer<ReceivedTurnData> listener = this.dataListener;
		if (listener != null) {
			listener.accept(received);
		} else {
			inboundQueue.offer(received);
		}
	}

	@Override
	public void close() {
		if (running && relayedAddress != null) {
			try {
				refresh(0L);
			} catch (Exception e) {
				LOGGER.debug("Best-effort TURN deallocation during close() failed: {}", e.getMessage());
			}
		}
		running = false;
		if (socket != null && !socket.isClosed()) {
			socket.close();
		}
		if (receiverThread != null && receiverThread != Thread.currentThread()) {
			try {
				receiverThread.join(1000);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
		for (CompletableFuture<MessageHeader> f : pendingRequests.values()) {
			f.cancel(true);
		}
		pendingRequests.clear();
		channelsByNumber.clear();
	}
}
