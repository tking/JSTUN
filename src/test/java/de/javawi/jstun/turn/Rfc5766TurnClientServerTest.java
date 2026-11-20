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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.attribute.ReservationToken;
import de.javawi.jstun.test.demo.TurnClientDemo;
import de.javawi.jstun.test.demo.ice.Candidate;
import de.javawi.jstun.test.demo.ice.Candidate.CandidateType;
import de.javawi.jstun.test.demo.ice.ICENegotiator;
import de.javawi.jstun.turn.TurnClient.ReceivedTurnData;
import de.javawi.jstun.util.Address;

/**
 * End-to-end tests for RFC 5766 (TURN) {@link TurnServer}, {@link TurnClient},
 * {@link TurnClientDemo}, and {@link ICENegotiator} relayed candidate gathering.
 */
public class Rfc5766TurnClientServerTest {

	static class UdpEchoPeer implements AutoCloseable {
		private final DatagramSocket socket;
		private final AtomicBoolean running = new AtomicBoolean(true);
		private final Thread thread;

		UdpEchoPeer(InetAddress bindAddr) throws Exception {
			this.socket = new DatagramSocket(0, bindAddr);
			this.socket.setSoTimeout(30);
			this.thread = new Thread(this::serve, "TurnTestEchoPeer");
			this.thread.setDaemon(true);
			this.thread.start();
		}

		InetSocketAddress getAddress() {
			return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
		}

		void sendRaw(InetSocketAddress target, byte[] payload) throws Exception {
			socket.send(new DatagramPacket(payload, payload.length, target.getAddress(), target.getPort()));
		}

		private void serve() {
			byte[] buf = new byte[4096];
			while (running.get() && !socket.isClosed()) {
				try {
					DatagramPacket pkt = new DatagramPacket(buf, buf.length);
					socket.receive(pkt);
					byte[] reply = new byte[pkt.getLength()];
					System.arraycopy(buf, 0, reply, 0, reply.length);
					socket.send(new DatagramPacket(reply, reply.length, pkt.getAddress(), pkt.getPort()));
				} catch (SocketTimeoutException ignored) {
					// poll
				} catch (Exception ignored) {
					break;
				}
			}
		}

		@Override
		public void close() throws Exception {
			running.set(false);
			socket.close();
			thread.join(500);
		}
	}

	private static Map<String, String> defaultUsers() {
		Map<String, String> users = new HashMap<String, String>();
		users.put("alice", "alice-secret");
		users.put("bob", "bob-secret");
		return users;
	}

	@Test
	public void testAllocatePermissionsSendDataIndicationAndChannelDataRoundTrip() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");
		try (TurnServer server = new TurnServer(loopback, 0, "turn.example.org", defaultUsers());
				UdpEchoPeer peer = new UdpEchoPeer(loopback)) {
			server.setAllowPrivateRelayPeers(true);
			server.setStatsIntervalSeconds(0);
			server.start();

			try (TurnClient client = new TurnClient(loopback, "127.0.0.1", server.getPort(), "alice", "alice-secret")) {
				client.setTimeoutInitValueMs(40);
				client.setMaxWaitTimeMs(200);

				// 1. Allocate (automatically handles 401 challenge)
				InetSocketAddress relayed = client.allocate();
				assertNotNull(relayed);
				assertNotNull(client.getMappedAddress());
				assertEquals("turn.example.org", client.getRealm());
				assertNotNull(client.getNonce());
				assertTrue(client.getLifetimeSeconds() > 0);
				assertEquals(1, server.getActiveAllocationCount());

				// 2. Unpermitted peer packet must be silently dropped by server
				peer.sendRaw(relayed, "unpermitted".getBytes(StandardCharsets.UTF_8));
				assertNull(client.receiveData(120));
				assertTrue(server.getStats().getDroppedNoPermission() >= 1);

				// 3. CreatePermission for multiple peer IPs
				client.createPermission(loopback, InetAddress.getByName("198.51.100.25"));

				// 4. SendIndication -> EchoPeer -> DataIndication
				byte[] indPayload = "hello-turn-indication".getBytes(StandardCharsets.UTF_8);
				client.sendDataIndication(peer.getAddress(), indPayload);
				ReceivedTurnData indReceived = client.receiveData(1000);
				assertNotNull(indReceived);
				assertFalse(indReceived.isViaChannel());
				assertEquals(-1, indReceived.getChannelNumber());
				assertEquals(peer.getAddress(), indReceived.getPeer());
				assertArrayEquals(indPayload, indReceived.getData());

				// 5. ChannelBind -> ChannelData -> EchoPeer -> ChannelData
				client.channelBind(0x4001, peer.getAddress());
				byte[] chPayload = "hello-turn-channel-data".getBytes(StandardCharsets.UTF_8);
				client.sendChannelData(0x4001, chPayload);
				ReceivedTurnData chReceived = client.receiveData(1000);
				assertNotNull(chReceived);
				assertTrue(chReceived.isViaChannel());
				assertEquals(0x4001, chReceived.getChannelNumber());
				assertEquals(peer.getAddress(), chReceived.getPeer());
				assertArrayEquals(chPayload, chReceived.getData());

				// 6. Conflicting ChannelBind on same channel number -> 400 Bad Request
				TurnException conflict = assertThrows(TurnException.class,
						() -> client.channelBind(0x4001, new InetSocketAddress(loopback, peer.getAddress().getPort() + 1)));
				assertEquals(400, conflict.getErrorCode());

				// 7. Refresh lifetime
				long refreshed = client.refresh(120L);
				assertEquals(120L, refreshed);
			}

			// close() sent Refresh(0), freeing the allocation
			assertEquals(0, server.getActiveAllocationCount());
			TurnServer.TurnServerStats stats = server.getStats();
			assertEquals(1, stats.getAllocationsCreated());
			assertTrue(stats.getAuthChallenges() >= 1);
			assertTrue(stats.getPermissionsCreated() >= 2);
			assertEquals(1, stats.getChannelsBound());
			assertEquals(1, stats.getSendIndicationsRelayed());
			assertEquals(1, stats.getDataIndicationsSent());
			assertEquals(1, stats.getChannelDataToPeer());
			assertEquals(1, stats.getChannelDataToClient());
			assertTrue(stats.getRefreshes() >= 2);
			assertTrue(stats.formatSummary(0).contains("allocCreated=1"));
		}
	}

	@Test
	public void testAuthenticationFailureStaleNonceAndSsrfProtection() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");
		try (TurnServer server = new TurnServer(loopback, 0, "turn.example.org", defaultUsers())) {
			// Default allowPrivateRelayPeers = false (SSRF protection active)
			server.setNonceValidityMs(60L);
			server.setStatsIntervalSeconds(0);
			server.start();

			// 1. Wrong password -> 401 Unauthorized
			try (TurnClient badClient = new TurnClient(loopback, "127.0.0.1", server.getPort(), "alice", "wrong-pass")) {
				badClient.setTimeoutInitValueMs(40);
				badClient.setMaxWaitTimeMs(200);
				TurnException ex = assertThrows(TurnException.class, badClient::allocate);
				assertEquals(401, ex.getErrorCode());
				assertTrue(server.getStats().getAuthFailures() >= 1);
			}

			// 2. Valid user: SSRF protection rejects private/loopback peer with 403 Forbidden
			try (TurnClient client = new TurnClient(loopback, "127.0.0.1", server.getPort(), "alice", "alice-secret")) {
				client.setTimeoutInitValueMs(40);
				client.setMaxWaitTimeMs(200);
				assertNotNull(client.allocate());

				TurnException perm403 = assertThrows(TurnException.class, () -> client.createPermission(loopback));
				assertEquals(403, perm403.getErrorCode());

				TurnException bind403 = assertThrows(TurnException.class,
						() -> client.channelBind(0x4002, new InetSocketAddress(loopback, 12345)));
				assertEquals(403, bind403.getErrorCode());
				assertTrue(server.getStats().getForbiddenPeers() >= 2);

				// 3. Wait for nonce to expire -> server returns 438 Stale Nonce, client retries transparently
				Thread.sleep(90);
				long refreshed = client.refresh(300L);
				assertEquals(300L, refreshed);
				assertTrue(server.getStats().getStaleNonces() >= 1);
			}
		}
	}

	@Test
	public void testEvenPortReservationTokenQuotasDemoAndIceRelayedCandidate() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");
		try (TurnServer server = new TurnServer(loopback, 0, "turn.example.org", defaultUsers())) {
			server.setAllowPrivateRelayPeers(true);
			server.setMaxAllocationsPerUser(2);
			server.setMaxTotalAllocations(2);
			server.setStatsIntervalSeconds(0);
			server.start();

			try (TurnClient client1 = new TurnClient(loopback, "127.0.0.1", server.getPort(), "alice", "alice-secret");
					TurnClient client2 = new TurnClient(loopback, "127.0.0.1", server.getPort(), "alice", "alice-secret");
					TurnClient client3 = new TurnClient(loopback, "127.0.0.1", server.getPort(), "alice", "alice-secret");
					TurnClient bobClient = new TurnClient(loopback, "127.0.0.1", server.getPort(), "bob", "bob-secret")) {
				client1.setTimeoutInitValueMs(40);
				client2.setTimeoutInitValueMs(40);
				client3.setTimeoutInitValueMs(40);
				bobClient.setTimeoutInitValueMs(40);

				// 1. EVEN-PORT with R=1 allocates even port and returns ReservationToken for port+1
				InetSocketAddress relay1 = client1.allocate(600L, true, true);
				assertEquals(0, relay1.getPort() % 2, "Expected even relay port, got " + relay1.getPort());
				ReservationToken token = client1.getReservationToken();
				assertNotNull(token);

				// 2. Claim reserved odd port with ReservationToken
				InetSocketAddress relay2 = client2.allocateWithReservationToken(token, 600L);
				assertEquals(relay1.getPort() + 1, relay2.getPort());

				// 3. Per-user quota (maxAllocationsPerUser = 2) -> 486 Allocation Quota Reached
				TurnException quota486 = assertThrows(TurnException.class, client3::allocate);
				assertEquals(486, quota486.getErrorCode());

				// 4. Global capacity (maxTotalAllocations = 2) -> 508 Insufficient Capacity for bob
				TurnException cap508 = assertThrows(TurnException.class, bobClient::allocate);
				assertEquals(508, cap508.getErrorCode());
			}

			// 5. ICENegotiator relayed candidate gathering against live TurnServer
			Candidate local = new Candidate(new Address("127.0.0.1"), (short) 1);
			try {
				ICENegotiator negotiator = new ICENegotiator((short) 1);
				negotiator.setTurnServer("127.0.0.1", server.getPort(), "alice", "alice-secret");
				Candidate relayed = negotiator.gatherRelayedCandidate(loopback, local);
				assertNotNull(relayed);
				assertEquals(CandidateType.Relayed, relayed.getCandidateType());
				assertEquals(local, relayed.getBase());
			} finally {
				local.closeSocket();
			}

			// 6. TurnClientDemo execution
			TurnClientDemo demo = new TurnClientDemo(loopback, "127.0.0.1", server.getPort(), "alice", "alice-secret");
			demo.run();
		}
	}
}
