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

package de.javawi.jstun.attribute;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.test.DiscoveryInfo;
import de.javawi.jstun.test.DiscoveryInfo.MappingBehavior;
import de.javawi.jstun.test.NatBehaviorDiscoveryTest;
import de.javawi.jstun.test.demo.StunServer;
import de.javawi.jstun.util.Address;

/**
 * Tests RFC 5389 and RFC 8489 features:
 * <ul>
 *   <li>Binding Indications ({@code 0x0011}) with no server response</li>
 *   <li>{@code 300 Try Alternate} + {@code ALTERNATE-SERVER} ({@code 0x8023}) redirect handling</li>
 *   <li>{@code MESSAGE-INTEGRITY-SHA256} ({@code 0x001C}, RFC 8489 §14.6)</li>
 *   <li>{@code USERHASH} ({@code 0x8029}, RFC 8489 §14.4)</li>
 * </ul>
 */
public class Rfc5389And8489Test {

	@Test
	public void testBindingIndicationRoundTripAndServerSilence() throws Exception {
		MessageHeader indication = new MessageHeader(MessageHeaderType.BindingIndication);
		indication.generateTransactionID();
		indication.addMessageAttribute(Software.jstun());
		byte[] wire = indication.getBytesWithFingerprint();

		assertEquals(MessageHeaderInterface.BINDINGINDICATION,
				MessageHeader.typeToInteger(MessageHeaderType.BindingIndication));
		MessageHeader parsed = MessageHeader.parseHeader(wire);
		assertEquals(MessageHeaderType.BindingIndication, parsed.getType());
		parsed.parseAttributes(wire);
		assertTrue(Fingerprint.verify(wire));

		// Start StunServer and confirm BindingIndication triggers no response
		InetAddress loopback = InetAddress.getByName("127.0.0.1");
		int[] ports = new int[4];
		DatagramSocket[] temp = new DatagramSocket[4];
		for (int i = 0; i < 4; i++) {
			temp[i] = new DatagramSocket(0, loopback);
			ports[i] = temp[i].getLocalPort();
		}
		for (DatagramSocket s : temp) {
			s.close();
		}

		StunServer server = new StunServer(ports[0], loopback, ports[1], loopback, ports[2], ports[3]);
		server.start();
		try (DatagramSocket client = new DatagramSocket(0, loopback)) {
			client.setSoTimeout(150);
			client.send(new DatagramPacket(wire, wire.length, loopback, ports[0]));
			DatagramPacket recv = new DatagramPacket(new byte[512], 512);
			assertThrows(SocketTimeoutException.class, () -> client.receive(recv));
		} finally {
			server.stop();
		}
	}

	@Test
	public void testAlternateServerRedirectAndLoopProtection() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");

		// Working target STUN server
		try (RedirectOrTargetServer target = new RedirectOrTargetServer(loopback, 0, false);
				RedirectOrTargetServer redirector = new RedirectOrTargetServer(loopback, target.getPort(), true)) {
			NatBehaviorDiscoveryTest test = new NatBehaviorDiscoveryTest(loopback, "127.0.0.1", redirector.getPort());
			test.setTimeoutInitValue(40);
			test.setMaxWaitTimeMs(80);
			DiscoveryInfo info = test.test();
			assertFalse(info.isError());
			assertEquals(MappingBehavior.DIRECT, info.getMappingBehavior());
		}

		// Redirect loop -> terminates cleanly after MAX_ALTERNATE_SERVER_REDIRECTS
		try (RedirectOrTargetServer loopServer = new RedirectOrTargetServer(loopback, -1, true)) {
			NatBehaviorDiscoveryTest loopTest = new NatBehaviorDiscoveryTest(loopback, "127.0.0.1",
					loopServer.getPort());
			loopTest.setTimeoutInitValue(30);
			loopTest.setMaxWaitTimeMs(50);
			DiscoveryInfo info = loopTest.test();
			assertTrue(info.isError());
		}
	}

	@Test
	public void testRfc8489MessageIntegritySha256AndUserhash() throws Exception {
		String username = "alice";
		String realm = "example.org";
		String password = "secret-password";

		MessageHeader mh = new MessageHeader(MessageHeaderType.BindingRequest);
		mh.generateTransactionID();

		Userhash uh = new Userhash(username, realm);
		assertTrue(uh.matches(username, realm));
		assertFalse(uh.matches("bob", realm));
		assertEquals(32, uh.getHash().length);
		mh.addMessageAttribute(uh);
		mh.addMessageAttribute(new Realm(realm));
		mh.addMessageAttribute(new Nonce("nonce-123"));

		byte[] prefixBeforeMi = mh.getBytes();
		byte[] shortHmac = MessageIntegritySha256.computeShortTermHMAC(prefixBeforeMi, password);
		MessageIntegritySha256 miShort = new MessageIntegritySha256(shortHmac);
		assertTrue(miShort.verifyShortTerm(prefixBeforeMi, password));
		assertFalse(miShort.verifyShortTerm(prefixBeforeMi, "wrong"));

		byte[] longHmac = MessageIntegritySha256.computeLongTermHMAC(prefixBeforeMi, username, realm, password);
		MessageIntegritySha256 miLong = new MessageIntegritySha256(longHmac);
		assertArrayEquals(longHmac, miLong.getHmac());
		assertTrue(miLong.verifyLongTerm(prefixBeforeMi, username, realm, password));
		assertFalse(miLong.verifyLongTerm(prefixBeforeMi, username, realm, "wrong"));

		mh.addMessageAttribute(miLong);
		byte[] packet = mh.getBytesWithFingerprint();
		assertTrue(Fingerprint.verify(packet));

		MessageHeader parsed = MessageHeader.parseHeader(packet);
		parsed.parseAttributes(packet);
		Userhash parsedUh = (Userhash) parsed.getMessageAttribute(MessageAttributeType.Userhash);
		assertNotNull(parsedUh);
		assertTrue(parsedUh.matches(username, realm));

		MessageIntegritySha256 parsedMi = (MessageIntegritySha256) parsed
				.getMessageAttribute(MessageAttributeType.MessageIntegritySha256);
		assertNotNull(parsedMi);
		assertArrayEquals(longHmac, parsedMi.getHmac());

		// Validation checks
		assertThrows(MessageAttributeException.class, () -> new MessageIntegritySha256(new byte[16]));
		assertThrows(MessageAttributeParsingException.class, () -> MessageIntegritySha256.parse(new byte[16]));
		assertThrows(de.javawi.jstun.util.UtilityException.class,
				() -> MessageIntegritySha256.computeShortTermHMAC(new byte[10], "secret"));
		assertThrows(MessageAttributeException.class, () -> new Userhash(new byte[16]));
		assertThrows(MessageAttributeParsingException.class, () -> Userhash.parse(new byte[16]));
	}

	static class RedirectOrTargetServer implements AutoCloseable {
		private final DatagramSocket socket;
		private final int redirectPort;
		private final boolean redirectMode;
		private final AtomicBoolean running = new AtomicBoolean(true);
		private final Thread thread;

		RedirectOrTargetServer(InetAddress addr, int redirectPort, boolean redirectMode) throws Exception {
			this.socket = new DatagramSocket(0, addr);
			this.socket.setSoTimeout(30);
			this.redirectPort = (redirectPort == -1) ? socket.getLocalPort() : redirectPort;
			this.redirectMode = redirectMode;
			this.thread = new Thread(this::serve, "SimAltServer");
			this.thread.setDaemon(true);
			this.thread.start();
		}

		int getPort() {
			return socket.getLocalPort();
		}

		private void serve() {
			byte[] buf = new byte[512];
			while (running.get() && !socket.isClosed()) {
				try {
					DatagramPacket pkt = new DatagramPacket(buf, buf.length);
					socket.receive(pkt);
					MessageHeader req = MessageHeader.parseHeader(pkt.getData());
					req.parseAttributes(pkt.getData());
					if (redirectMode) {
						MessageHeader err = new MessageHeader(MessageHeaderType.BindingErrorResponse);
						err.setTransactionID(req.getTransactionID());
						ErrorCode ec = new ErrorCode();
						ec.setResponseCode(300);
						err.addMessageAttribute(ec);
						AlternateServer alt = new AlternateServer();
						alt.setAddress(new Address(pkt.getAddress().getAddress()));
						alt.setPort(redirectPort);
						err.addMessageAttribute(alt);
						byte[] out = err.getBytesWithFingerprint();
						socket.send(new DatagramPacket(out, out.length, pkt.getAddress(), pkt.getPort()));
					} else {
						MessageHeader resp = new MessageHeader(MessageHeaderType.BindingResponse);
						resp.setTransactionID(req.getTransactionID());
						XorMappedAddress xma = new XorMappedAddress(req.getTransactionID());
						xma.setAddress(new Address(pkt.getAddress().getAddress()));
						xma.setPort(pkt.getPort());
						resp.addMessageAttribute(xma);
						byte[] out = resp.getBytesWithFingerprint();
						socket.send(new DatagramPacket(out, out.length, pkt.getAddress(), pkt.getPort()));
					}
				} catch (SocketTimeoutException ignored) {
				} catch (Exception ignored) {
				}
			}
		}

		@Override
		public void close() {
			running.set(false);
			socket.close();
		}
	}
}
