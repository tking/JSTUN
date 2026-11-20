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
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.SimpleFormatter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.attribute.ChannelNumber;
import de.javawi.jstun.attribute.Data;
import de.javawi.jstun.attribute.ErrorCode;
import de.javawi.jstun.attribute.EvenPort;
import de.javawi.jstun.attribute.Fingerprint;
import de.javawi.jstun.attribute.Lifetime;
import de.javawi.jstun.attribute.MessageAttribute;
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
import de.javawi.jstun.util.JstunVersion;
import de.javawi.jstun.util.UtilityException;

/**
 * Lightweight, NIO {@link Selector}-based RFC 5766 (TURN) UDP Relay Server.
 * <p>
 * Implements mandatory long-term credential authentication (RFC 5389 §10.2 / RFC 5766 §4),
 * 5-tuple allocations with {@code LIFETIME}, {@code EVEN-PORT} + {@code RESERVATION-TOKEN},
 * {@code Refresh}, {@code CreatePermission}, {@code Send}/{@code Data} indications,
 * {@code ChannelBind} + {@code ChannelData} relaying, SSRF peer filtering (RFC 5766 §17),
 * per-user/global quotas, and zero-dependency observability counters.
 */
public class TurnServer implements AutoCloseable {
	private static final Logger LOGGER = LoggerFactory.getLogger(TurnServer.class);
	private static final int BUFFER_SIZE = 10240;
	public static final long DEFAULT_LIFETIME_SECONDS = 600L;
	public static final long MAX_LIFETIME_SECONDS = 3600L;
	public static final long PERMISSION_LIFETIME_MS = 300_000L;
	public static final long CHANNEL_LIFETIME_MS = 600_000L;
	public static final long RESERVATION_LIFETIME_MS = 30_000L;
	private static final long DEFAULT_NONCE_VALIDITY_MS = 600_000L;
	private static final int EVEN_PORT_BIND_ATTEMPTS = 64;

	private final InetAddress bindAddress;
	private final int requestedPort;
	private final InetAddress relayAddress;
	private final String realm;
	private final Map<String, String> userPasswords;
	private final byte[] nonceSecret = new byte[32];
	private final SecureRandom secureRandom = new SecureRandom();
	private final Software software = Software.jstun();
	private final TurnServerStats stats = new TurnServerStats();

	private long defaultLifetimeSeconds = DEFAULT_LIFETIME_SECONDS;
	private long nonceValidityMs = DEFAULT_NONCE_VALIDITY_MS;
	private int maxAllocationsPerUser = 10;
	private int maxTotalAllocations = 100;
	private boolean allowPrivateRelayPeers = false;
	private long statsIntervalSeconds = 60L;

	private volatile boolean running;
	private Selector selector;
	private DatagramChannel serverChannel;
	private Thread selectorThread;
	private ScheduledExecutorService maintenanceScheduler;

	// State owned/accessed by selector thread (and read by stats/reaper)
	private final Map<InetSocketAddress, Allocation> allocationsByClient = new ConcurrentHashMap<InetSocketAddress, Allocation>();
	private final Map<DatagramChannel, Allocation> allocationsByRelayChannel = new ConcurrentHashMap<DatagramChannel, Allocation>();
	private final Map<ReservationToken, ReservedPort> reservations = new ConcurrentHashMap<ReservationToken, ReservedPort>();

	public static final class TurnServerStats {
		final AtomicLong allocationsCreated = new AtomicLong();
		final AtomicLong allocationsExpired = new AtomicLong();
		final AtomicLong refreshes = new AtomicLong();
		final AtomicLong permissionsCreated = new AtomicLong();
		final AtomicLong channelsBound = new AtomicLong();
		final AtomicLong sendIndicationsRelayed = new AtomicLong();
		final AtomicLong dataIndicationsSent = new AtomicLong();
		final AtomicLong channelDataToPeer = new AtomicLong();
		final AtomicLong channelDataToClient = new AtomicLong();
		final AtomicLong authChallenges = new AtomicLong();
		final AtomicLong authFailures = new AtomicLong();
		final AtomicLong staleNonces = new AtomicLong();
		final AtomicLong forbiddenPeers = new AtomicLong();
		final AtomicLong droppedNoPermission = new AtomicLong();

		public long getAllocationsCreated() { return allocationsCreated.get(); }
		public long getAllocationsExpired() { return allocationsExpired.get(); }
		public long getRefreshes() { return refreshes.get(); }
		public long getPermissionsCreated() { return permissionsCreated.get(); }
		public long getChannelsBound() { return channelsBound.get(); }
		public long getSendIndicationsRelayed() { return sendIndicationsRelayed.get(); }
		public long getDataIndicationsSent() { return dataIndicationsSent.get(); }
		public long getChannelDataToPeer() { return channelDataToPeer.get(); }
		public long getChannelDataToClient() { return channelDataToClient.get(); }
		public long getAuthChallenges() { return authChallenges.get(); }
		public long getAuthFailures() { return authFailures.get(); }
		public long getStaleNonces() { return staleNonces.get(); }
		public long getForbiddenPeers() { return forbiddenPeers.get(); }
		public long getDroppedNoPermission() { return droppedNoPermission.get(); }

		public String formatSummary(int activeAllocations) {
			return "activeAlloc=" + activeAllocations
					+ " allocCreated=" + allocationsCreated.get()
					+ " allocExpired=" + allocationsExpired.get()
					+ " refreshes=" + refreshes.get()
					+ " perms=" + permissionsCreated.get()
					+ " channels=" + channelsBound.get()
					+ " sendInd=" + sendIndicationsRelayed.get()
					+ " dataInd=" + dataIndicationsSent.get()
					+ " chToPeer=" + channelDataToPeer.get()
					+ " chToClient=" + channelDataToClient.get()
					+ " auth401=" + authChallenges.get()
					+ " authFail=" + authFailures.get()
					+ " stale438=" + staleNonces.get()
					+ " forbidden403=" + forbiddenPeers.get()
					+ " droppedNoPerm=" + droppedNoPermission.get();
		}
	}

	private static final class Allocation {
		final InetSocketAddress clientAddress;
		final String username;
		final DatagramChannel relayChannel;
		final InetSocketAddress relayedAddress;
		final byte[] allocateTxId;
		volatile long expiresAtMs;
		// Peer IP -> expiry timestamp (ms)
		final Map<InetAddress, Long> permissions = new ConcurrentHashMap<InetAddress, Long>();
		// Channel number -> binding
		final Map<Integer, ChannelBinding> channelsByNumber = new ConcurrentHashMap<Integer, ChannelBinding>();
		// Peer socket address -> channel number
		final Map<InetSocketAddress, Integer> channelsByPeer = new ConcurrentHashMap<InetSocketAddress, Integer>();

		Allocation(InetSocketAddress clientAddress, String username, DatagramChannel relayChannel,
				InetSocketAddress relayedAddress, byte[] allocateTxId, long expiresAtMs) {
			this.clientAddress = clientAddress;
			this.username = username;
			this.relayChannel = relayChannel;
			this.relayedAddress = relayedAddress;
			this.allocateTxId = Arrays.copyOf(allocateTxId, allocateTxId.length);
			this.expiresAtMs = expiresAtMs;
		}
	}

	private static final class ChannelBinding {
		final int channelNumber;
		final InetSocketAddress peer;
		volatile long expiresAtMs;

		ChannelBinding(int channelNumber, InetSocketAddress peer, long expiresAtMs) {
			this.channelNumber = channelNumber;
			this.peer = peer;
			this.expiresAtMs = expiresAtMs;
		}
	}

	private static final class ReservedPort {
		final DatagramChannel channel;
		final InetSocketAddress address;
		final long expiresAtMs;

		ReservedPort(DatagramChannel channel, InetSocketAddress address, long expiresAtMs) {
			this.channel = channel;
			this.address = address;
			this.expiresAtMs = expiresAtMs;
		}
	}

	public TurnServer(InetAddress bindAddress, int port, String realm, Map<String, String> userPasswords) {
		this(bindAddress, port, bindAddress, realm, userPasswords);
	}

	public TurnServer(InetAddress bindAddress, int port, InetAddress relayAddress, String realm,
			Map<String, String> userPasswords) {
		if (bindAddress == null || relayAddress == null) {
			throw new IllegalArgumentException("Bind and relay addresses must not be null");
		}
		if (realm == null || realm.trim().isEmpty()) {
			throw new IllegalArgumentException("TURN realm must not be null or empty");
		}
		if (userPasswords == null || userPasswords.isEmpty()) {
			throw new IllegalArgumentException("At least one TURN user credential is required");
		}
		this.bindAddress = bindAddress;
		this.requestedPort = port;
		this.relayAddress = relayAddress;
		this.realm = realm.trim();
		this.userPasswords = new ConcurrentHashMap<String, String>(userPasswords);
		this.secureRandom.nextBytes(this.nonceSecret);
	}

	public TurnServerStats getStats() {
		return stats;
	}

	public int getActiveAllocationCount() {
		return allocationsByClient.size();
	}

	public int getPort() {
		if (serverChannel != null && serverChannel.socket() != null) {
			return serverChannel.socket().getLocalPort();
		}
		return requestedPort;
	}

	public String getRealm() {
		return realm;
	}

	public void setDefaultLifetimeSeconds(long defaultLifetimeSeconds) {
		this.defaultLifetimeSeconds = Math.max(1L, Math.min(MAX_LIFETIME_SECONDS, defaultLifetimeSeconds));
	}

	public void setNonceValidityMs(long nonceValidityMs) {
		this.nonceValidityMs = Math.max(1L, nonceValidityMs);
	}

	public void setMaxAllocationsPerUser(int maxAllocationsPerUser) {
		this.maxAllocationsPerUser = Math.max(1, maxAllocationsPerUser);
	}

	public void setMaxTotalAllocations(int maxTotalAllocations) {
		this.maxTotalAllocations = Math.max(1, maxTotalAllocations);
	}

	public void setAllowPrivateRelayPeers(boolean allowPrivateRelayPeers) {
		this.allowPrivateRelayPeers = allowPrivateRelayPeers;
	}

	public void setStatsIntervalSeconds(long statsIntervalSeconds) {
		this.statsIntervalSeconds = statsIntervalSeconds;
	}

	public synchronized void start() throws IOException {
		if (running) {
			return;
		}
		selector = Selector.open();
		serverChannel = DatagramChannel.open();
		serverChannel.configureBlocking(false);
		serverChannel.socket().setReceiveBufferSize(65536);
		serverChannel.socket().setSendBufferSize(65536);
		serverChannel.bind(new InetSocketAddress(bindAddress, requestedPort));
		serverChannel.register(selector, SelectionKey.OP_READ);

		running = true;
		String endpoint = formatEndpoint(bindAddress, getPort());
		selectorThread = new Thread(this::eventLoop, "turn-server-" + endpoint);
		selectorThread.start();

		maintenanceScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "turn-maintenance");
			t.setDaemon(true);
			return t;
		});
		maintenanceScheduler.scheduleAtFixedRate(() -> {
			if (selector != null) {
				selector.wakeup();
			}
		}, 1, 1, TimeUnit.SECONDS);
		if (statsIntervalSeconds > 0) {
			maintenanceScheduler.scheduleAtFixedRate(
					() -> LOGGER.info("TURN Server stats: {}", stats.formatSummary(allocationsByClient.size())),
					statsIntervalSeconds, statsIntervalSeconds, TimeUnit.SECONDS);
		}
		LOGGER.info("TURN Server ({}) listening on {} (realm='{}', allowPrivatePeers={}).",
				JstunVersion.SOFTWARE, endpoint, realm, allowPrivateRelayPeers);
	}

	public synchronized void stop() {
		if (!running) {
			return;
		}
		running = false;
		if (maintenanceScheduler != null) {
			maintenanceScheduler.shutdownNow();
		}
		if (selector != null) {
			selector.wakeup();
		}
		if (selectorThread != null) {
			try {
				selectorThread.join(5000);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
		cleanupAllResources();
		LOGGER.info("TURN Server stopped. Final stats: {}", stats.formatSummary(allocationsByClient.size()));
	}

	@Override
	public void close() {
		stop();
	}

	private void cleanupAllResources() {
		for (Allocation alloc : allocationsByClient.values()) {
			closeQuietly(alloc.relayChannel);
		}
		allocationsByClient.clear();
		allocationsByRelayChannel.clear();
		for (ReservedPort rp : reservations.values()) {
			closeQuietly(rp.channel);
		}
		reservations.clear();
		closeQuietly(serverChannel);
		if (selector != null) {
			try {
				selector.close();
			} catch (IOException ignored) {
				// ignore
			}
		}
	}

	private void eventLoop() {
		ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
		long lastReapMs = System.currentTimeMillis();
		while (running) {
			try {
				selector.select(500);
				Iterator<SelectionKey> it = selector.selectedKeys().iterator();
				while (it.hasNext()) {
					SelectionKey key = it.next();
					it.remove();
					if (!key.isValid() || !key.isReadable()) {
						continue;
					}
					DatagramChannel ch = (DatagramChannel) key.channel();
					buffer.clear();
					SocketAddress remote = ch.receive(buffer);
					if (remote == null || !(remote instanceof InetSocketAddress)) {
						continue;
					}
					buffer.flip();
					byte[] packet = new byte[buffer.remaining()];
					buffer.get(packet);
					InetSocketAddress remoteAddr = (InetSocketAddress) remote;

					if (ch == serverChannel) {
						handleClientPacket(remoteAddr, packet);
					} else {
						Allocation alloc = allocationsByRelayChannel.get(ch);
						if (alloc != null) {
							handlePeerPacket(alloc, remoteAddr, packet);
						}
					}
				}
				long now = System.currentTimeMillis();
				if (now - lastReapMs >= 1000L) {
					reapExpired(now);
					lastReapMs = now;
				}
			} catch (IOException ioe) {
				if (running) {
					LOGGER.error("IOException in TURN server event loop: {}", ioe.getMessage(), ioe);
				}
			} catch (RuntimeException re) {
				LOGGER.warn("Unexpected RuntimeException in TURN server event loop: {}", re.getMessage(), re);
			}
		}
	}

	private void reapExpired(long now) {
		Iterator<Map.Entry<InetSocketAddress, Allocation>> it = allocationsByClient.entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry<InetSocketAddress, Allocation> entry = it.next();
			Allocation alloc = entry.getValue();
			if (now >= alloc.expiresAtMs) {
				it.remove();
				allocationsByRelayChannel.remove(alloc.relayChannel);
				closeQuietly(alloc.relayChannel);
				stats.allocationsExpired.incrementAndGet();
				LOGGER.debug("Expired TURN allocation {} for client {}.",
						formatEndpoint(alloc.relayedAddress.getAddress(), alloc.relayedAddress.getPort()),
						formatEndpoint(alloc.clientAddress.getAddress(), alloc.clientAddress.getPort()));
			} else {
				alloc.permissions.entrySet().removeIf(e -> now >= e.getValue());
				Iterator<Map.Entry<Integer, ChannelBinding>> chIt = alloc.channelsByNumber.entrySet().iterator();
				while (chIt.hasNext()) {
					ChannelBinding cb = chIt.next().getValue();
					if (now >= cb.expiresAtMs) {
						chIt.remove();
						alloc.channelsByPeer.remove(cb.peer, cb.channelNumber);
					}
				}
			}
		}
		Iterator<Map.Entry<ReservationToken, ReservedPort>> resIt = reservations.entrySet().iterator();
		while (resIt.hasNext()) {
			ReservedPort rp = resIt.next().getValue();
			if (now >= rp.expiresAtMs) {
				resIt.remove();
				closeQuietly(rp.channel);
			}
		}
	}

	private void handleClientPacket(InetSocketAddress clientAddr, byte[] packet) {
		try {
			if (ChannelData.isChannelData(packet)) {
				handleClientChannelData(clientAddr, packet);
				return;
			}
			MessageHeader req = MessageHeader.parseHeader(packet);
			req.parseAttributes(packet);
			if (req.getMessageAttribute(MessageAttributeType.Fingerprint) != null && !Fingerprint.verify(packet)) {
				LOGGER.warn("Discarding TURN packet with invalid FINGERPRINT from {}.",
						formatEndpoint(clientAddr.getAddress(), clientAddr.getPort()));
				return;
			}
			MessageHeaderType type = req.getType();
			if (type == MessageHeaderType.SendIndication) {
				handleSendIndication(clientAddr, req);
			} else if (type == MessageHeaderType.AllocateRequest) {
				handleAllocateRequest(clientAddr, req, packet);
			} else if (type == MessageHeaderType.RefreshRequest) {
				handleRefreshRequest(clientAddr, req, packet);
			} else if (type == MessageHeaderType.CreatePermissionRequest) {
				handleCreatePermissionRequest(clientAddr, req, packet);
			} else if (type == MessageHeaderType.ChannelBindRequest) {
				handleChannelBindRequest(clientAddr, req, packet);
			} else if (type == MessageHeaderType.BindingRequest) {
				handleBindingRequest(clientAddr, req);
			}
		} catch (MessageHeaderParsingException | MessageAttributeException
				| UtilityException | IOException e) {
			LOGGER.warn("Error handling TURN packet ({} bytes) from {}: {}",
					packet.length, formatEndpoint(clientAddr.getAddress(), clientAddr.getPort()), e.getMessage());
		}
	}

	private void handleBindingRequest(InetSocketAddress clientAddr, MessageHeader req)
			throws UtilityException, MessageAttributeException, IOException {
		MessageHeader resp = new MessageHeader(MessageHeaderType.BindingResponse);
		resp.setTransactionID(req.getTransactionID());
		XorMappedAddress xma = new XorMappedAddress(req.getTransactionID());
		xma.setAddress(new Address(clientAddr.getAddress().getAddress()));
		xma.setPort(clientAddr.getPort());
		resp.addMessageAttribute(xma);
		resp.addMessageAttribute(software);
		sendToClient(clientAddr, resp.getBytesWithFingerprint());
	}

	private String authenticate(InetSocketAddress clientAddr, MessageHeader req, byte[] rawPacket,
			MessageHeaderType errorType) throws UtilityException, MessageAttributeException, IOException {
		Username userAttr = (Username) req.getMessageAttribute(MessageAttributeType.Username);
		Realm realmAttr = (Realm) req.getMessageAttribute(MessageAttributeType.Realm);
		Nonce nonceAttr = (Nonce) req.getMessageAttribute(MessageAttributeType.Nonce);
		MessageAttribute miAttr = req.getMessageAttribute(MessageAttributeType.MessageIntegrity);

		if (userAttr == null || realmAttr == null || nonceAttr == null || miAttr == null) {
			stats.authChallenges.incrementAndGet();
			sendAuthError(clientAddr, req, errorType, 401);
			return null;
		}
		String username = userAttr.getUsername();
		String password = userPasswords.get(username);
		if (password == null || !realm.equals(realmAttr.getRealm())) {
			stats.authFailures.incrementAndGet();
			sendAuthError(clientAddr, req, errorType, 401);
			return null;
		}
		NonceStatus nonceStatus = verifyNonce(clientAddr.getAddress(), nonceAttr.getNonce());
		if (nonceStatus == NonceStatus.STALE) {
			stats.staleNonces.incrementAndGet();
			sendAuthError(clientAddr, req, errorType, 438);
			return null;
		}
		if (nonceStatus == NonceStatus.INVALID) {
			stats.authFailures.incrementAndGet();
			sendAuthError(clientAddr, req, errorType, 401);
			return null;
		}
		try {
			if (!MessageHeader.verifyLongTermMessageIntegrity(rawPacket, username, realm, password)) {
				stats.authFailures.incrementAndGet();
				sendAuthError(clientAddr, req, errorType, 401);
				return null;
			}
		} catch (MessageAttributeParsingException e) {
			stats.authFailures.incrementAndGet();
			sendAuthError(clientAddr, req, errorType, 401);
			return null;
		}
		return username;
	}

	private void handleAllocateRequest(InetSocketAddress clientAddr, MessageHeader req, byte[] rawPacket)
			throws UtilityException, MessageAttributeException, IOException {
		String username = authenticate(clientAddr, req, rawPacket, MessageHeaderType.AllocateErrorResponse);
		if (username == null) {
			return;
		}
		String password = userPasswords.get(username);

		Allocation existing = allocationsByClient.get(clientAddr);
		if (existing != null) {
			if (!Arrays.equals(existing.allocateTxId, req.getTransactionID())) {
				sendError(clientAddr, req, MessageHeaderType.AllocateErrorResponse, 437, username, password);
				return;
			}
			// Idempotent retransmission of same Allocate request
			sendAllocateSuccess(clientAddr, req, existing, null, username, password);
			return;
		}

		RequestedTransport rt = (RequestedTransport) req.getMessageAttribute(MessageAttributeType.RequestedTransport);
		if (rt == null) {
			sendError(clientAddr, req, MessageHeaderType.AllocateErrorResponse, 400, username, password);
			return;
		}
		if (rt.getProtocol() != RequestedTransport.PROTOCOL_UDP) {
			sendError(clientAddr, req, MessageHeaderType.AllocateErrorResponse, 442, username, password);
			return;
		}

		EvenPort evenPort = (EvenPort) req.getMessageAttribute(MessageAttributeType.EvenPort);
		ReservationToken reqToken = (ReservationToken) req.getMessageAttribute(MessageAttributeType.ReservationToken);
		if (evenPort != null && reqToken != null) {
			sendError(clientAddr, req, MessageHeaderType.AllocateErrorResponse, 400, username, password);
			return;
		}

		// Quota checks (RFC 5766 §6.2)
		long userCount = allocationsByClient.values().stream().filter(a -> username.equals(a.username)).count();
		if (userCount >= maxAllocationsPerUser) {
			sendError(clientAddr, req, MessageHeaderType.AllocateErrorResponse, 486, username, password);
			return;
		}
		if (allocationsByClient.size() >= maxTotalAllocations) {
			sendError(clientAddr, req, MessageHeaderType.AllocateErrorResponse, 508, username, password);
			return;
		}

		long lifetimeSec = defaultLifetimeSeconds;
		Lifetime reqLifetime = (Lifetime) req.getMessageAttribute(MessageAttributeType.Lifetime);
		if (reqLifetime != null) {
			lifetimeSec = Math.max(1L, Math.min(MAX_LIFETIME_SECONDS, reqLifetime.getLifetime()));
		}

		DatagramChannel relayChannel;
		ReservationToken issuedToken = null;
		if (reqToken != null) {
			ReservedPort rp = reservations.remove(reqToken);
			if (rp == null || System.currentTimeMillis() >= rp.expiresAtMs) {
				if (rp != null) {
					closeQuietly(rp.channel);
				}
				sendError(clientAddr, req, MessageHeaderType.AllocateErrorResponse, 508, username, password);
				return;
			}
			relayChannel = rp.channel;
		} else if (evenPort != null) {
			DatagramChannel[] pair = allocateEvenPort(evenPort.isReserveNextPort());
			if (pair == null) {
				sendError(clientAddr, req, MessageHeaderType.AllocateErrorResponse, 508, username, password);
				return;
			}
			relayChannel = pair[0];
			if (pair[1] != null) {
				byte[] tokBytes = new byte[ReservationToken.TOKEN_LENGTH];
				secureRandom.nextBytes(tokBytes);
				issuedToken = new ReservationToken(tokBytes);
				InetSocketAddress reservedAddr = (InetSocketAddress) pair[1].getLocalAddress();
				reservations.put(issuedToken,
						new ReservedPort(pair[1], reservedAddr, System.currentTimeMillis() + RESERVATION_LIFETIME_MS));
			}
		} else {
			relayChannel = openRelayChannel(0);
		}

		relayChannel.configureBlocking(false);
		relayChannel.register(selector, SelectionKey.OP_READ);
		InetSocketAddress relayedAddr = (InetSocketAddress) relayChannel.getLocalAddress();
		Allocation alloc = new Allocation(clientAddr, username, relayChannel, relayedAddr, req.getTransactionID(),
				System.currentTimeMillis() + lifetimeSec * 1000L);
		allocationsByClient.put(clientAddr, alloc);
		allocationsByRelayChannel.put(relayChannel, alloc);
		stats.allocationsCreated.incrementAndGet();

		LOGGER.info("TURN Allocate: user='{}' client={} -> relay={} (lifetime={}s).",
				username, formatEndpoint(clientAddr.getAddress(), clientAddr.getPort()),
				formatEndpoint(relayedAddr.getAddress(), relayedAddr.getPort()), lifetimeSec);
		sendAllocateSuccess(clientAddr, req, alloc, issuedToken, username, password);
	}

	private void sendAllocateSuccess(InetSocketAddress clientAddr, MessageHeader req, Allocation alloc,
			ReservationToken issuedToken, String username, String password)
			throws UtilityException, MessageAttributeException, IOException {
		long remainingSec = Math.max(1L, (alloc.expiresAtMs - System.currentTimeMillis() + 999L) / 1000L);
		MessageHeader resp = new MessageHeader(MessageHeaderType.AllocateResponse);
		resp.setTransactionID(req.getTransactionID());

		XorRelayedAddress xra = new XorRelayedAddress(req.getTransactionID());
		xra.setAddress(new Address(alloc.relayedAddress.getAddress().getAddress()));
		xra.setPort(alloc.relayedAddress.getPort());
		resp.addMessageAttribute(xra);

		resp.addMessageAttribute(new Lifetime(remainingSec));

		XorMappedAddress xma = new XorMappedAddress(req.getTransactionID());
		xma.setAddress(new Address(clientAddr.getAddress().getAddress()));
		xma.setPort(clientAddr.getPort());
		resp.addMessageAttribute(xma);

		if (issuedToken != null) {
			resp.addMessageAttribute(issuedToken);
		}
		resp.addMessageAttribute(software);
		sendToClient(clientAddr, resp.getBytesWithLongTermMessageIntegrityAndFingerprint(username, realm, password));
	}

	private void handleRefreshRequest(InetSocketAddress clientAddr, MessageHeader req, byte[] rawPacket)
			throws UtilityException, MessageAttributeException, IOException {
		String username = authenticate(clientAddr, req, rawPacket, MessageHeaderType.RefreshErrorResponse);
		if (username == null) {
			return;
		}
		String password = userPasswords.get(username);
		Allocation alloc = allocationsByClient.get(clientAddr);
		if (alloc == null) {
			sendError(clientAddr, req, MessageHeaderType.RefreshErrorResponse, 437, username, password);
			return;
		}
		if (!username.equals(alloc.username)) {
			sendError(clientAddr, req, MessageHeaderType.RefreshErrorResponse, 441, username, password);
			return;
		}

		long grantedLifetime = defaultLifetimeSeconds;
		Lifetime reqLifetime = (Lifetime) req.getMessageAttribute(MessageAttributeType.Lifetime);
		if (reqLifetime != null) {
			grantedLifetime = Math.min(MAX_LIFETIME_SECONDS, reqLifetime.getLifetime());
		}

		if (grantedLifetime == 0L) {
			allocationsByClient.remove(clientAddr);
			allocationsByRelayChannel.remove(alloc.relayChannel);
			closeQuietly(alloc.relayChannel);
			LOGGER.info("TURN Refresh(0): deleted allocation {} for user='{}'.",
					formatEndpoint(alloc.relayedAddress.getAddress(), alloc.relayedAddress.getPort()), username);
		} else {
			alloc.expiresAtMs = System.currentTimeMillis() + grantedLifetime * 1000L;
		}
		stats.refreshes.incrementAndGet();

		MessageHeader resp = new MessageHeader(MessageHeaderType.RefreshResponse);
		resp.setTransactionID(req.getTransactionID());
		resp.addMessageAttribute(new Lifetime(grantedLifetime));
		resp.addMessageAttribute(software);
		sendToClient(clientAddr, resp.getBytesWithLongTermMessageIntegrityAndFingerprint(username, realm, password));
	}

	private void handleCreatePermissionRequest(InetSocketAddress clientAddr, MessageHeader req, byte[] rawPacket)
			throws UtilityException, MessageAttributeException, IOException {
		String username = authenticate(clientAddr, req, rawPacket, MessageHeaderType.CreatePermissionErrorResponse);
		if (username == null) {
			return;
		}
		String password = userPasswords.get(username);
		Allocation alloc = allocationsByClient.get(clientAddr);
		if (alloc == null) {
			sendError(clientAddr, req, MessageHeaderType.CreatePermissionErrorResponse, 437, username, password);
			return;
		}
		if (!username.equals(alloc.username)) {
			sendError(clientAddr, req, MessageHeaderType.CreatePermissionErrorResponse, 441, username, password);
			return;
		}

		List<MessageAttribute> peerAttrs = req.getMessageAttributes(MessageAttributeType.XorPeerAddress);
		if (peerAttrs.isEmpty()) {
			sendError(clientAddr, req, MessageHeaderType.CreatePermissionErrorResponse, 400, username, password);
			return;
		}

		// Validate all peer IPs before mutating state
		InetAddress[] peerIps = new InetAddress[peerAttrs.size()];
		for (int i = 0; i < peerAttrs.size(); i++) {
			XorPeerAddress xpa = (XorPeerAddress) peerAttrs.get(i);
			InetAddress peerIp = xpa.getAddress().getInetAddress();
			if (!isPeerAddressAllowed(peerIp)) {
				stats.forbiddenPeers.incrementAndGet();
				LOGGER.warn("TURN CreatePermission rejected forbidden peer {} for user='{}'.",
						peerIp.getHostAddress(), username);
				sendError(clientAddr, req, MessageHeaderType.CreatePermissionErrorResponse, 403, username, password);
				return;
			}
			peerIps[i] = peerIp;
		}

		long expiry = System.currentTimeMillis() + PERMISSION_LIFETIME_MS;
		for (InetAddress peerIp : peerIps) {
			alloc.permissions.put(peerIp, expiry);
			stats.permissionsCreated.incrementAndGet();
		}

		MessageHeader resp = new MessageHeader(MessageHeaderType.CreatePermissionResponse);
		resp.setTransactionID(req.getTransactionID());
		resp.addMessageAttribute(software);
		sendToClient(clientAddr, resp.getBytesWithLongTermMessageIntegrityAndFingerprint(username, realm, password));
	}

	private void handleChannelBindRequest(InetSocketAddress clientAddr, MessageHeader req, byte[] rawPacket)
			throws UtilityException, MessageAttributeException, IOException {
		String username = authenticate(clientAddr, req, rawPacket, MessageHeaderType.ChannelBindErrorResponse);
		if (username == null) {
			return;
		}
		String password = userPasswords.get(username);
		Allocation alloc = allocationsByClient.get(clientAddr);
		if (alloc == null) {
			sendError(clientAddr, req, MessageHeaderType.ChannelBindErrorResponse, 437, username, password);
			return;
		}
		if (!username.equals(alloc.username)) {
			sendError(clientAddr, req, MessageHeaderType.ChannelBindErrorResponse, 441, username, password);
			return;
		}

		ChannelNumber chAttr = (ChannelNumber) req.getMessageAttribute(MessageAttributeType.ChannelNumber);
		XorPeerAddress peerAttr = (XorPeerAddress) req.getMessageAttribute(MessageAttributeType.XorPeerAddress);
		if (chAttr == null || peerAttr == null || peerAttr.getPort() <= 0) {
			sendError(clientAddr, req, MessageHeaderType.ChannelBindErrorResponse, 400, username, password);
			return;
		}

		InetAddress peerIp = peerAttr.getAddress().getInetAddress();
		if (!isPeerAddressAllowed(peerIp)) {
			stats.forbiddenPeers.incrementAndGet();
			LOGGER.warn("TURN ChannelBind rejected forbidden peer {} for user='{}'.",
					peerIp.getHostAddress(), username);
			sendError(clientAddr, req, MessageHeaderType.ChannelBindErrorResponse, 403, username, password);
			return;
		}

		int chNum = chAttr.getChannelNumber();
		InetSocketAddress peerSock = new InetSocketAddress(peerIp, peerAttr.getPort());
		long now = System.currentTimeMillis();

		// RFC 5766 §11.2: channel number and peer transport address must be uniquely bound 1-to-1
		ChannelBinding existingCh = alloc.channelsByNumber.get(chNum);
		if (existingCh != null && now < existingCh.expiresAtMs && !existingCh.peer.equals(peerSock)) {
			sendError(clientAddr, req, MessageHeaderType.ChannelBindErrorResponse, 400, username, password);
			return;
		}
		Integer existingPeerCh = alloc.channelsByPeer.get(peerSock);
		if (existingPeerCh != null && existingPeerCh.intValue() != chNum) {
			ChannelBinding other = alloc.channelsByNumber.get(existingPeerCh);
			if (other != null && now < other.expiresAtMs) {
				sendError(clientAddr, req, MessageHeaderType.ChannelBindErrorResponse, 400, username, password);
				return;
			}
		}

		ChannelBinding binding = new ChannelBinding(chNum, peerSock, now + CHANNEL_LIFETIME_MS);
		alloc.channelsByNumber.put(chNum, binding);
		alloc.channelsByPeer.put(peerSock, chNum);
		// RFC 5766 §11.2: ChannelBind also installs/refreshes a permission for the peer IP
		alloc.permissions.put(peerIp, now + PERMISSION_LIFETIME_MS);
		stats.channelsBound.incrementAndGet();

		MessageHeader resp = new MessageHeader(MessageHeaderType.ChannelBindResponse);
		resp.setTransactionID(req.getTransactionID());
		resp.addMessageAttribute(software);
		sendToClient(clientAddr, resp.getBytesWithLongTermMessageIntegrityAndFingerprint(username, realm, password));
	}

	private void handleSendIndication(InetSocketAddress clientAddr, MessageHeader req)
			throws UtilityException, IOException {
		Allocation alloc = allocationsByClient.get(clientAddr);
		if (alloc == null) {
			return;
		}
		XorPeerAddress peerAttr = (XorPeerAddress) req.getMessageAttribute(MessageAttributeType.XorPeerAddress);
		Data dataAttr = (Data) req.getMessageAttribute(MessageAttributeType.Data);
		if (peerAttr == null || dataAttr == null || peerAttr.getPort() <= 0) {
			return;
		}
		InetAddress peerIp = peerAttr.getAddress().getInetAddress();
		Long permExpiry = alloc.permissions.get(peerIp);
		if (permExpiry == null || System.currentTimeMillis() >= permExpiry) {
			stats.droppedNoPermission.incrementAndGet();
			return;
		}
		byte[] payload = dataAttr.getData();
		alloc.relayChannel.send(ByteBuffer.wrap(payload), new InetSocketAddress(peerIp, peerAttr.getPort()));
		stats.sendIndicationsRelayed.incrementAndGet();
	}

	private void handleClientChannelData(InetSocketAddress clientAddr, byte[] packet)
			throws MessageAttributeParsingException, IOException {
		Allocation alloc = allocationsByClient.get(clientAddr);
		if (alloc == null) {
			return;
		}
		ChannelData cd = ChannelData.parse(packet);
		ChannelBinding binding = alloc.channelsByNumber.get(cd.getChannelNumber());
		if (binding == null || System.currentTimeMillis() >= binding.expiresAtMs) {
			return;
		}
		alloc.relayChannel.send(ByteBuffer.wrap(cd.getData()), binding.peer);
		stats.channelDataToPeer.incrementAndGet();
	}

	private void handlePeerPacket(Allocation alloc, InetSocketAddress peerAddr, byte[] payload) {
		try {
			long now = System.currentTimeMillis();
			Long permExpiry = alloc.permissions.get(peerAddr.getAddress());
			if (permExpiry == null || now >= permExpiry) {
				stats.droppedNoPermission.incrementAndGet();
				return;
			}
			Integer boundChannel = alloc.channelsByPeer.get(peerAddr);
			if (boundChannel != null) {
				ChannelBinding cb = alloc.channelsByNumber.get(boundChannel);
				if (cb != null && now < cb.expiresAtMs) {
					ChannelData cd = new ChannelData(boundChannel, payload);
					sendToClient(alloc.clientAddress, cd.getBytes());
					stats.channelDataToClient.incrementAndGet();
					return;
				}
			}
			MessageHeader dataInd = new MessageHeader(MessageHeaderType.DataIndication);
			dataInd.generateTransactionID();
			XorPeerAddress xpa = new XorPeerAddress(dataInd.getTransactionID());
			xpa.setAddress(new Address(peerAddr.getAddress().getAddress()));
			xpa.setPort(peerAddr.getPort());
			dataInd.addMessageAttribute(xpa);
			dataInd.addMessageAttribute(new Data(payload));
			sendToClient(alloc.clientAddress, dataInd.getBytesWithFingerprint());
			stats.dataIndicationsSent.incrementAndGet();
		} catch (Exception e) {
			LOGGER.warn("Error relaying peer packet from {} to client {}: {}",
					formatEndpoint(peerAddr.getAddress(), peerAddr.getPort()),
					formatEndpoint(alloc.clientAddress.getAddress(), alloc.clientAddress.getPort()),
					e.getMessage());
		}
	}

	private DatagramChannel openRelayChannel(int port) throws IOException {
		DatagramChannel ch = DatagramChannel.open();
		ch.socket().setReceiveBufferSize(65536);
		ch.socket().setSendBufferSize(65536);
		ch.bind(new InetSocketAddress(relayAddress, port));
		return ch;
	}

	private DatagramChannel[] allocateEvenPort(boolean reserveNext) {
		for (int attempt = 0; attempt < EVEN_PORT_BIND_ATTEMPTS; attempt++) {
			int candidateEvenPort = 49152 + (secureRandom.nextInt(8000) * 2);
			DatagramChannel evenCh = null;
			DatagramChannel oddCh = null;
			try {
				evenCh = openRelayChannel(candidateEvenPort);
				if (reserveNext) {
					oddCh = openRelayChannel(candidateEvenPort + 1);
				}
				return new DatagramChannel[] { evenCh, oddCh };
			} catch (IOException e) {
				closeQuietly(evenCh);
				closeQuietly(oddCh);
			}
		}
		return null;
	}

	boolean isPeerAddressAllowed(InetAddress peerIp) {
		if (peerIp == null || peerIp.isAnyLocalAddress() || peerIp.isMulticastAddress()) {
			return false;
		}
		if (allowPrivateRelayPeers) {
			return true;
		}
		if (peerIp.isLoopbackAddress() || peerIp.isLinkLocalAddress() || peerIp.isSiteLocalAddress()) {
			return false;
		}
		if (peerIp.equals(bindAddress) || peerIp.equals(relayAddress)) {
			return false;
		}
		// Reject IPv4 broadcast (255.255.255.255) and CGNAT 100.64.0.0/10
		byte[] b = peerIp.getAddress();
		if (b.length == 4) {
			int b0 = b[0] & 0xFF;
			int b1 = b[1] & 0xFF;
			if (b0 == 255 && (b[1] & 0xFF) == 255 && (b[2] & 0xFF) == 255 && (b[3] & 0xFF) == 255) {
				return false;
			}
			if (b0 == 100 && (b1 >= 64 && b1 <= 127)) {
				return false;
			}
		}
		return true;
	}

	private void sendAuthError(InetSocketAddress clientAddr, MessageHeader req, MessageHeaderType errorType, int code)
			throws UtilityException, MessageAttributeException, IOException {
		MessageHeader err = new MessageHeader(errorType);
		err.setTransactionID(req.getTransactionID());
		ErrorCode ec = new ErrorCode();
		ec.setResponseCode(code);
		err.addMessageAttribute(ec);
		err.addMessageAttribute(new Realm(realm));
		err.addMessageAttribute(new Nonce(generateNonce(clientAddr.getAddress())));
		err.addMessageAttribute(software);
		sendToClient(clientAddr, err.getBytesWithFingerprint());
	}

	private void sendError(InetSocketAddress clientAddr, MessageHeader req, MessageHeaderType errorType, int code,
			String username, String password) throws UtilityException, MessageAttributeException, IOException {
		MessageHeader err = new MessageHeader(errorType);
		err.setTransactionID(req.getTransactionID());
		ErrorCode ec = new ErrorCode();
		ec.setResponseCode(code);
		err.addMessageAttribute(ec);
		err.addMessageAttribute(software);
		sendToClient(clientAddr, err.getBytesWithLongTermMessageIntegrityAndFingerprint(username, realm, password));
	}

	private void sendToClient(InetSocketAddress clientAddr, byte[] data) throws IOException {
		serverChannel.send(ByteBuffer.wrap(data), clientAddr);
	}

	private enum NonceStatus {
		VALID, STALE, INVALID
	}

	String generateNonce(InetAddress clientIp) throws UtilityException {
		long ts = System.currentTimeMillis();
		String tsHex = Long.toHexString(ts);
		String sig = computeNonceMac(clientIp.getHostAddress(), tsHex);
		return tsHex + "." + sig;
	}

	private NonceStatus verifyNonce(InetAddress clientIp, String nonce) {
		if (nonce == null) {
			return NonceStatus.INVALID;
		}
		int dot = nonce.indexOf('.');
		if (dot <= 0 || dot >= nonce.length() - 1) {
			return NonceStatus.INVALID;
		}
		String tsHex = nonce.substring(0, dot);
		String providedSig = nonce.substring(dot + 1);
		long ts;
		try {
			ts = Long.parseLong(tsHex, 16);
		} catch (NumberFormatException e) {
			return NonceStatus.INVALID;
		}
		try {
			String expectedSig = computeNonceMac(clientIp.getHostAddress(), tsHex);
			if (!MessageDigest.isEqual(
					providedSig.getBytes(StandardCharsets.US_ASCII),
					expectedSig.getBytes(StandardCharsets.US_ASCII))) {
				return NonceStatus.INVALID;
			}
		} catch (UtilityException e) {
			return NonceStatus.INVALID;
		}
		long age = System.currentTimeMillis() - ts;
		if (age < -5000L || age > nonceValidityMs) {
			return NonceStatus.STALE;
		}
		return NonceStatus.VALID;
	}

	private String computeNonceMac(String clientIp, String tsHex) throws UtilityException {
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(new SecretKeySpec(nonceSecret, "HmacSHA256"));
			byte[] digest = mac.doFinal((clientIp + ":" + tsHex).getBytes(StandardCharsets.UTF_8));
			StringBuilder sb = new StringBuilder(32);
			for (int i = 0; i < 16; i++) {
				sb.append(String.format(Locale.ROOT, "%02x", digest[i] & 0xFF));
			}
			return sb.toString();
		} catch (GeneralSecurityException e) {
			throw new UtilityException("Failed to compute nonce HMAC: " + e.getMessage());
		}
	}

	private static void closeQuietly(DatagramChannel ch) {
		if (ch != null) {
			try {
				ch.close();
			} catch (IOException ignored) {
				// ignore
			}
		}
	}

	static String formatEndpoint(InetAddress address, int port) {
		String host = address.getHostAddress();
		if (address instanceof Inet6Address) {
			return "[" + host + "]:" + port;
		}
		return host + ":" + port;
	}

	public static void main(String[] args) {
		try {
			if (args.length < 4) {
				System.out.println("usage: java de.javawi.jstun.turn.TurnServer PORT IP REALM USER:PASS [USER2:PASS2 ...]");
				System.exit(0);
			}
			int port = Integer.parseInt(args[0]);
			InetAddress ip = InetAddress.getByName(args[1]);
			String realm = args[2];
			Map<String, String> users = new HashMap<String, String>();
			for (int i = 3; i < args.length; i++) {
				int colon = args[i].indexOf(':');
				if (colon <= 0 || colon >= args[i].length() - 1) {
					throw new IllegalArgumentException("Invalid credential (expected USER:PASS): " + args[i]);
				}
				users.put(args[i].substring(0, colon), args[i].substring(colon + 1));
			}

			String levelProp = System.getProperty("jstun.log.level", "INFO");
			Level level = Level.parse(levelProp.trim().toUpperCase(Locale.ROOT));
			Handler fh = new FileHandler("logging_turn_server.%g.txt", 10 * 1024 * 1024, 5, true);
			fh.setFormatter(new SimpleFormatter());
			fh.setLevel(level);
			java.util.logging.Logger jul = java.util.logging.Logger.getLogger("de.javawi.jstun");
			jul.addHandler(fh);
			jul.setLevel(level);

			TurnServer server = new TurnServer(ip, port, realm, Collections.unmodifiableMap(users));
			Runtime.getRuntime().addShutdownHook(new Thread(server::stop, "turn-shutdown-hook"));
			server.start();
		} catch (Exception e) {
			LOGGER.error("Failed to start TURN server: {}", e.getMessage(), e);
		}
	}
}
