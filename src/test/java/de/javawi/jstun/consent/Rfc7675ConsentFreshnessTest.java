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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.attribute.ErrorCode;
import de.javawi.jstun.attribute.Fingerprint;
import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.attribute.Priority;
import de.javawi.jstun.attribute.Username;
import de.javawi.jstun.attribute.XorMappedAddress;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.test.demo.ConsentFreshnessDemo;
import de.javawi.jstun.util.Address;

/**
 * Comprehensive unit and loopback UDP integration tests for RFC 7675
 * (STUN Usage for Consent Freshness).
 */
public class Rfc7675ConsentFreshnessTest {

	private static final String UFRAG = "remoteUfrag:localUfrag";
	private static final String PASS = "VOkJxbRl1RmTxUk/WvJxBt";

	@Test
	public void testMessageHeaderShortTermIntegrityHelpers() throws Exception {
		MessageHeader mh = new MessageHeader(MessageHeaderType.BindingRequest);
		mh.generateTransactionID();
		mh.addMessageAttribute(new Username(UFRAG));
		mh.addMessageAttribute(new Priority(0x6e0001ffL));

		byte[] miOnly = mh.getBytesWithShortTermMessageIntegrity(PASS);
		assertTrue(MessageHeader.verifyShortTermMessageIntegrity(miOnly, PASS));
		assertFalse(MessageHeader.verifyShortTermMessageIntegrity(miOnly, "wrongPass"));

		byte[] miAndFp = mh.getBytesWithShortTermMessageIntegrityAndFingerprint(PASS);
		assertTrue(MessageHeader.verifyShortTermMessageIntegrity(miAndFp, PASS));
		assertTrue(Fingerprint.verify(miAndFp));

		// Tampering invalidates both FINGERPRINT and MESSAGE-INTEGRITY
		byte[] tampered = Arrays.copyOf(miAndFp, miAndFp.length);
		tampered[25] ^= 0x01;
		assertFalse(Fingerprint.verify(tampered));
		assertFalse(MessageHeader.verifyShortTermMessageIntegrity(tampered, PASS));
	}

	@Test
	public void testRfc7675ValidationAndRandomizationBounds() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");
		try (DatagramSocket sock = new DatagramSocket(0, loopback)) {
			InetSocketAddress peer = new InetSocketAddress(loopback, 3478);

			// Invalid arguments rejected
			assertThrows(IllegalArgumentException.class, () -> new ConsentSession((DatagramSocket) null, peer, UFRAG, PASS));
			assertThrows(IllegalArgumentException.class, () -> new ConsentSession(sock, null, UFRAG, PASS));
			assertThrows(IllegalArgumentException.class, () -> new ConsentSession(sock, peer, "", PASS));
			assertThrows(IllegalArgumentException.class, () -> new ConsentSession(sock, peer, UFRAG, ""));
			// RFC 7675 §5.1: MUST NOT set period between checks to less than 4 seconds
			assertThrows(IllegalArgumentException.class,
					() -> new ConsentSession(sock, peer, UFRAG, PASS, 4_000L, 30_000L));
			assertThrows(IllegalArgumentException.class,
					() -> new ConsentSession(sock, peer, UFRAG, PASS, 5_000L, 3_000L));

			try (ConsentSession session = new ConsentSession(sock, peer, UFRAG, PASS)) {
				assertEquals(ConsentState.INITIAL, session.getState());
				assertEquals(ConsentSession.DEFAULT_CHECK_INTERVAL_MS, session.getBaseIntervalMs());
				assertEquals(ConsentSession.DEFAULT_CONSENT_EXPIRY_MS, session.getConsentExpiryMs());
				assertFalse(session.canSendApplicationData());
				assertEquals(0L, session.getRemainingConsentMs());
				assertThrows(IllegalStateException.class, () -> session.sendApplicationData(new byte[] { 1, 2, 3 }));

				// Priority bounds & DiffServ traffic class (RFC 7675 §6)
				session.setPriority(0x6e0001ffL);
				assertThrows(IllegalArgumentException.class, () -> session.setPriority(-2L));
				assertThrows(IllegalArgumentException.class, () -> session.setPriority(0x100000000L));
				session.setTrafficClass(0xB8); // EF DSCP

				// Verify [0.8 * 5000, 1.2 * 5000] = [4000, 6000] ms randomization
				long minSeen = Long.MAX_VALUE;
				long maxSeen = Long.MIN_VALUE;
				for (int i = 0; i < 200; i++) {
					long interval = session.nextRandomizedIntervalMs();
					assertTrue(interval >= 4_000L && interval <= 6_000L,
							"Randomized interval out of [4000, 6000] ms: " + interval);
					minSeen = Math.min(minSeen, interval);
					maxSeen = Math.max(maxSeen, interval);
				}
				assertTrue(maxSeen > minSeen, "Intervals should vary randomly");
			}
		}
	}

	@Test
	public void testFullConsentLifecycleExpirationAndNoCredentialReuse() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");
		AtomicLong virtualClock = new AtomicLong(1_000_000L);

		try (DatagramSocket clientSock = new DatagramSocket(0, loopback);
				DatagramSocket peerSock = new DatagramSocket(0, loopback)) {
			peerSock.setSoTimeout(1000);
			InetSocketAddress peerAddr = new InetSocketAddress(loopback, peerSock.getLocalPort());
			InetSocketAddress clientAddr = new InetSocketAddress(loopback, clientSock.getLocalPort());

			ConsentResponder responder = new ConsentResponder(UFRAG, PASS);
			try (ConsentSession session = new ConsentSession(
					clientSock, false, peerAddr, UFRAG, PASS,
					5_000L, 30_000L, virtualClock::get, true)) {
				session.setPriority(0x6e0001ffL);

				AtomicInteger obtainedCount = new AtomicInteger();
				AtomicInteger refreshedCount = new AtomicInteger();
				AtomicInteger expiredCount = new AtomicInteger();
				session.setListener(new ConsentListener() {
					@Override
					public void onConsentObtained(ConsentSession s) {
						obtainedCount.incrementAndGet();
					}

					@Override
					public void onConsentRefreshed(ConsentSession s, long rttMs) {
						refreshedCount.incrementAndGet();
					}

					@Override
					public void onConsentExpired(ConsentSession s) {
						expiredCount.incrementAndGet();
					}
				});

				// 1. Before consent: application data is forbidden (RFC 7675 §5.1)
				assertFalse(session.canSendApplicationData());
				assertThrows(IllegalStateException.class, () -> session.sendApplicationData("blocked".getBytes(StandardCharsets.UTF_8)));

				// 2. Send first consent check and receive at peer
				session.sendConsentCheck();
				assertEquals(1L, session.getChecksSent());
				assertEquals(1, session.getOutstandingTransactionCount());

				DatagramPacket reqPkt1 = new DatagramPacket(new byte[2048], 2048);
				peerSock.receive(reqPkt1);
				byte[] req1Bytes = Arrays.copyOf(reqPkt1.getData(), reqPkt1.getLength());
				assertTrue(ConsentSession.isStunPacket(req1Bytes, req1Bytes.length));

				byte[] resp1Bytes = responder.handleRequest(req1Bytes, clientAddr);
				assertNotNull(resp1Bytes);
				assertEquals(1L, responder.getRequestsHandled());

				// Advance clock by 25ms to simulate RTT
				virtualClock.addAndGet(25L);
				assertTrue(session.processIncomingPacket(resp1Bytes, peerAddr));

				assertEquals(ConsentState.ACTIVE, session.getState());
				assertTrue(session.canSendApplicationData());
				assertEquals(1, obtainedCount.get());
				assertEquals(1, refreshedCount.get());
				assertEquals(25L, session.getLastRttMs());
				assertEquals(25L, session.getSmoothedRttMs());
				assertEquals(30_000L, session.getRemainingConsentMs());
				assertEquals(0, session.getOutstandingTransactionCount());

				// Replay of the same response must be ignored (TX ID already consumed)
				assertFalse(session.processIncomingPacket(resp1Bytes, peerAddr));

				// Application data now succeeds!
				byte[] appMsg = "media-packet-1".getBytes(StandardCharsets.UTF_8);
				session.sendApplicationData(appMsg);
				DatagramPacket appRecv = new DatagramPacket(new byte[256], 256);
				peerSock.receive(appRecv);
				assertArrayEquals(appMsg, Arrays.copyOf(appRecv.getData(), appRecv.getLength()));

				// 3. Out-of-order / previous transaction response accepted (RFC 7675 §5.1)
				virtualClock.addAndGet(5_000L);
				session.sendConsentCheck(); // Check #2
				DatagramPacket reqPkt2 = new DatagramPacket(new byte[2048], 2048);
				peerSock.receive(reqPkt2);
				byte[] req2Bytes = Arrays.copyOf(reqPkt2.getData(), reqPkt2.getLength());

				virtualClock.addAndGet(5_000L);
				session.sendConsentCheck(); // Check #3
				DatagramPacket reqPkt3 = new DatagramPacket(new byte[2048], 2048);
				peerSock.receive(reqPkt3);
				byte[] req3Bytes = Arrays.copyOf(reqPkt3.getData(), reqPkt3.getLength());
				assertEquals(2, session.getOutstandingTransactionCount());

				// Peer replies to Check #2 (earlier request) while Check #3 is still in flight
				byte[] resp2Bytes = responder.handleRequest(req2Bytes, clientAddr);
				virtualClock.addAndGet(40L);
				assertTrue(session.processIncomingPacket(resp2Bytes, peerAddr));
				assertEquals(2, refreshedCount.get());
				assertEquals(30_000L, session.getRemainingConsentMs());
				assertEquals(1, session.getOutstandingTransactionCount()); // Check #3 still pending

				// 4. Unauthenticated close (e.g. TCP FIN) MUST NOT revoke consent (§5.2)
				session.onUnauthenticatedClose("TCP FIN");
				assertEquals(ConsentState.ACTIVE, session.getState());

				// 5. Advance virtual clock by 29,999 ms -> still ACTIVE (1 ms remaining)
				virtualClock.addAndGet(29_999L);
				assertEquals(ConsentState.ACTIVE, session.getState());
				assertEquals(1L, session.getRemainingConsentMs());

				// Advance 1 more ms -> 30,000 ms elapsed -> EXPIRED!
				virtualClock.addAndGet(1L);
				assertTrue(session.checkExpiration());
				assertEquals(ConsentState.EXPIRED, session.getState());
				assertEquals(1, expiredCount.get());
				assertEquals(0, session.getOutstandingTransactionCount()); // All outstanding TX discarded
				assertFalse(session.canSendApplicationData());
				assertThrows(IllegalStateException.class, () -> session.sendApplicationData(appMsg));

				// 6. Late valid response to Check #3 after expiry MUST NOT re-establish consent (§5.1)
				byte[] resp3Bytes = responder.handleRequest(req3Bytes, clientAddr);
				assertFalse(session.processIncomingPacket(resp3Bytes, peerAddr));
				assertEquals(ConsentState.EXPIRED, session.getState());

				// 7. Same credentials MUST NOT be reused after consent loss (§5.1)
				assertThrows(IllegalStateException.class, session::sendConsentCheck);
				assertThrows(IllegalStateException.class, session::start);
				assertThrows(IllegalStateException.class, session::markInitialConsentObtained);
				assertThrows(IllegalArgumentException.class, () -> session.restartWithNewCredentials(UFRAG, PASS));

				// Restarting with fresh ICE credentials succeeds on the same 5-tuple
				try (ConsentSession restarted = session.restartWithNewCredentials("newRemote:newLocal", "newFreshPassword1234")) {
					assertEquals(ConsentState.INITIAL, restarted.getState());
					restarted.markInitialConsentObtained();
					assertEquals(ConsentState.ACTIVE, restarted.getState());
				}
			}
		}
	}

	@Test
	public void testImmediateRevocation403AndUnauthenticatedRejection() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");
		AtomicLong virtualClock = new AtomicLong(2_000_000L);

		try (DatagramSocket clientSock = new DatagramSocket(0, loopback);
				DatagramSocket peerSock = new DatagramSocket(0, loopback)) {
			peerSock.setSoTimeout(1000);
			InetSocketAddress peerAddr = new InetSocketAddress(loopback, peerSock.getLocalPort());
			InetSocketAddress clientAddr = new InetSocketAddress(loopback, clientSock.getLocalPort());

			ConsentResponder responder = new ConsentResponder(UFRAG, PASS);
			try (ConsentSession session = new ConsentSession(
					clientSock, false, peerAddr, UFRAG, PASS,
					5_000L, 30_000L, virtualClock::get, true)) {
				AtomicReference<String> revokedReason = new AtomicReference<>();
				session.setListener(new ConsentListener() {
					@Override
					public void onConsentRevoked(ConsentSession s, String reason) {
						revokedReason.set(reason);
					}
				});

				// Obtain initial consent
				session.markInitialConsentObtained();
				assertEquals(ConsentState.ACTIVE, session.getState());

				// Send consent check
				session.sendConsentCheck();
				DatagramPacket reqPkt = new DatagramPacket(new byte[2048], 2048);
				peerSock.receive(reqPkt);
				byte[] reqBytes = Arrays.copyOf(reqPkt.getData(), reqPkt.getLength());
				MessageHeader parsedReq = MessageHeader.parseHeader(reqBytes);
				parsedReq.parseAttributes(reqBytes);

				// 1. Spoofed source IP/port MUST be ignored
				byte[] validResp = responder.handleRequest(reqBytes, clientAddr);
				assertFalse(session.processIncomingPacket(validResp, new InetSocketAddress(loopback, peerSock.getLocalPort() + 1)));
				assertEquals(1, session.getOutstandingTransactionCount());

				// 2. Unauthenticated 403 Forbidden (wrong password) MUST be ignored (RFC 7675 §5.2)
				MessageHeader fake403 = new MessageHeader(MessageHeaderType.BindingErrorResponse);
				fake403.setTransactionID(parsedReq.getTransactionID());
				ErrorCode ec403 = new ErrorCode();
				ec403.setResponseCode(403);
				fake403.addMessageAttribute(ec403);
				byte[] badAuth403 = fake403.getBytesWithShortTermMessageIntegrityAndFingerprint("wrong-attacker-password");
				assertFalse(session.processIncomingPacket(badAuth403, peerAddr));
				assertEquals(ConsentState.ACTIVE, session.getState());
				assertNull(revokedReason.get());
				assertEquals(1, session.getOutstandingTransactionCount()); // TX still preserved!

				// 3. Corrupt FINGERPRINT MUST be ignored
				byte[] badFp = Arrays.copyOf(validResp, validResp.length);
				badFp[badFp.length - 1] ^= 0xFF;
				assertFalse(session.processIncomingPacket(badFp, peerAddr));

				// 4. Non-403 authenticated STUN error (e.g. 500 Server Error) does NOT revoke immediately
				MessageHeader err500 = new MessageHeader(MessageHeaderType.BindingErrorResponse);
				err500.setTransactionID(parsedReq.getTransactionID());
				ErrorCode ec500 = new ErrorCode();
				ec500.setResponseCode(500);
				err500.addMessageAttribute(ec500);
				byte[] auth500 = err500.getBytesWithShortTermMessageIntegrityAndFingerprint(PASS);
				virtualClock.addAndGet(1000L);
				assertTrue(session.processIncomingPacket(auth500, peerAddr));
				assertEquals(ConsentState.ACTIVE, session.getState());
				assertEquals(29_000L, session.getRemainingConsentMs()); // Not refreshed!

				// 5. Authenticated 403 Forbidden from responder IMMEDIATELY revokes consent (RFC 7675 §5.2)
				responder.setConsentGranted(false);
				assertFalse(responder.isConsentGranted());
				session.sendConsentCheck();
				DatagramPacket reqPkt2 = new DatagramPacket(new byte[2048], 2048);
				peerSock.receive(reqPkt2);
				byte[] req2Bytes = Arrays.copyOf(reqPkt2.getData(), reqPkt2.getLength());
				byte[] auth403 = responder.handleRequest(req2Bytes, clientAddr);
				assertNotNull(auth403);
				assertEquals(1L, responder.getRevocationsSent());

				assertTrue(session.processIncomingPacket(auth403, peerAddr));
				assertEquals(ConsentState.REVOKED, session.getState());
				assertFalse(session.canSendApplicationData());
				assertEquals(0, session.getOutstandingTransactionCount());
				assertNotNull(revokedReason.get());
				assertTrue(revokedReason.get().contains("403"));
			}
		}
	}

	@Test
	public void testAuthenticatedCloseRevocation() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");
		try (ConsentSession session = new ConsentSession(
				loopback, new InetSocketAddress(loopback, 55555), UFRAG, PASS)) {
			AtomicReference<String> reasonRef = new AtomicReference<>();
			session.setListener(new ConsentListener() {
				@Override
				public void onConsentRevoked(ConsentSession s, String reason) {
					reasonRef.set(reason);
				}
			});
			session.markInitialConsentObtained();
			assertTrue(session.canSendApplicationData());

			session.revokeByAuthenticatedClose("DTLS fatal close_notify alert");
			assertEquals(ConsentState.REVOKED, session.getState());
			assertFalse(session.canSendApplicationData());
			assertEquals("DTLS fatal close_notify alert", reasonRef.get());
		}
	}

	@Test
	public void testScheduledLiveUdpLoopbackAndDemuxAndResponderFiltering() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");
		CountDownLatch obtained = new CountDownLatch(1);
		CountDownLatch refreshedTwice = new CountDownLatch(2);
		CountDownLatch appDataReceived = new CountDownLatch(1);
		CountDownLatch expired = new CountDownLatch(1);
		List<byte[]> receivedAppPackets = new ArrayList<>();

		try (ConsentResponder responder = new ConsentResponder(loopback, 0, UFRAG, PASS)) {
			responder.start();
			InetSocketAddress responderAddr = responder.getLocalAddress();
			assertNotNull(responderAddr);

			try (DatagramSocket clientSock = new DatagramSocket(0, loopback);
					ConsentSession session = new ConsentSession(
							clientSock, false, responderAddr, UFRAG, PASS,
							80L, 450L, System::currentTimeMillis, false)) {
				session.setListener(new ConsentListener() {
					@Override
					public void onConsentObtained(ConsentSession s) {
						obtained.countDown();
					}

					@Override
					public void onConsentRefreshed(ConsentSession s, long rttMs) {
						refreshedTwice.countDown();
					}

					@Override
					public void onConsentExpired(ConsentSession s) {
						expired.countDown();
					}
				});
				session.setApplicationDataHandler((data, src) -> {
					receivedAppPackets.add(data);
					appDataReceived.countDown();
				});

				session.start();
				assertTrue(obtained.await(3, TimeUnit.SECONDS), "Initial consent should be obtained over UDP");
				assertTrue(refreshedTwice.await(3, TimeUnit.SECONDS), "Periodic consent refresh should occur");
				assertEquals(ConsentState.ACTIVE, session.getState());
				assertTrue(session.getResponsesReceived() >= 2L);

				// Send non-STUN application packet back to clientSock -> verify demux to applicationDataHandler
				try (DatagramSocket appSender = new DatagramSocket(0, loopback)) {
					byte[] rtpLike = new byte[] { (byte) 0x80, 0x60, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44 };
					appSender.send(new DatagramPacket(rtpLike, rtpLike.length,
							loopback, session.getLocalAddress().getPort()));
					assertTrue(appDataReceived.await(2, TimeUnit.SECONDS));
					assertArrayEquals(rtpLike, receivedAppPackets.get(0));
				}

				// Switch responder to silent revocation -> session expires naturally
				responder.setSilentWhenRevoked(true);
				responder.setConsentGranted(false);
				assertTrue(expired.await(3, TimeUnit.SECONDS), "Session should expire when peer goes silent");
				assertEquals(ConsentState.EXPIRED, session.getState());
			}
		}

		// Responder input filtering unit checks
		ConsentResponder stateless = new ConsentResponder(UFRAG, PASS);
		assertThrows(IllegalStateException.class, stateless::start);
		assertNull(stateless.getLocalAddress());
		assertNull(stateless.handleRequest(null, new InetSocketAddress(loopback, 1234)));
		assertNull(stateless.handleRequest(new byte[10], new InetSocketAddress(loopback, 1234)));

		// Wrong username dropped
		MessageHeader wrongUserReq = new MessageHeader(MessageHeaderType.BindingRequest);
		wrongUserReq.generateTransactionID();
		wrongUserReq.addMessageAttribute(new Username("other:user"));
		byte[] wrongUserWire = wrongUserReq.getBytesWithShortTermMessageIntegrityAndFingerprint(PASS);
		assertNull(stateless.handleRequest(wrongUserWire, new InetSocketAddress(loopback, 1234)));

		// Bad password dropped
		MessageHeader badPassReq = new MessageHeader(MessageHeaderType.BindingRequest);
		badPassReq.generateTransactionID();
		badPassReq.addMessageAttribute(new Username(UFRAG));
		byte[] badPassWire = badPassReq.getBytesWithShortTermMessageIntegrityAndFingerprint("wrongPass");
		assertNull(stateless.handleRequest(badPassWire, new InetSocketAddress(loopback, 1234)));

		// Valid request produces signed BindingResponse with XOR-MAPPED-ADDRESS
		MessageHeader okReq = new MessageHeader(MessageHeaderType.BindingRequest);
		okReq.generateTransactionID();
		okReq.addMessageAttribute(new Username(UFRAG));
		byte[] okWire = okReq.getBytesWithShortTermMessageIntegrityAndFingerprint(PASS);
		byte[] okResp = stateless.handleRequest(okWire, new InetSocketAddress(loopback, 4321));
		assertNotNull(okResp);
		MessageHeader parsedResp = MessageHeader.parseHeader(okResp);
		parsedResp.parseAttributes(okResp);
		assertEquals(MessageHeaderType.BindingResponse, parsedResp.getType());
		XorMappedAddress xma = (XorMappedAddress) parsedResp.getMessageAttribute(MessageAttributeType.XorMappedAddress);
		assertNotNull(xma);
		assertEquals(4321, xma.getPort());
		assertEquals(new Address("127.0.0.1"), xma.getAddress());
	}

	@Test
	public void testConsentFreshnessDemoLoopback() throws Exception {
		ConsentFreshnessDemo.main(new String[0]);
	}
}
