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

package de.javawi.jstun.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.attribute.ChangeRequest;
import de.javawi.jstun.attribute.ChangedAddress;
import de.javawi.jstun.attribute.ErrorCode;
import de.javawi.jstun.attribute.Fingerprint;
import de.javawi.jstun.attribute.MappedAddress;
import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.attribute.OtherAddress;
import de.javawi.jstun.attribute.Padding;
import de.javawi.jstun.attribute.ResponseAddress;
import de.javawi.jstun.attribute.ResponseOrigin;
import de.javawi.jstun.attribute.ResponsePort;
import de.javawi.jstun.attribute.Software;
import de.javawi.jstun.attribute.SourceAddress;
import de.javawi.jstun.attribute.UnknownAttribute;
import de.javawi.jstun.attribute.XorMappedAddress;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.test.demo.StunServer;
import de.javawi.jstun.util.Address;
import de.javawi.jstun.util.JstunVersion;

/**
 * Tests the RFC 3489 Section 10.2 UDP Binding Lifetime binary search algorithm
 * ({@link BindingLifetimeTest}) and the dual-homed {@link StunServer} implementation.
 */
public class BindingLifetimeAndStunServerTest {

	enum LifetimeServerMode {
		NORMAL,
		XOR_MAPPED_ONLY,
		INITIAL_ERROR,
		INITIAL_MISSING_MAPPED,
		PROBE_ERROR,
		ALWAYS_TIMEOUT,
		ALWAYS_SUCCEED
	}

	/**
	 * Simulated STUN server for BindingLifetimeTest supporting multiple response
	 * modes to exercise every branch of the binary search and error handling.
	 */
	static class SimulatedLifetimeServer implements AutoCloseable {
		private final DatagramSocket socket;
		private final AtomicBoolean running = new AtomicBoolean(true);
		private final AtomicInteger responseAddressProbeCount = new AtomicInteger(0);
		private final LifetimeServerMode mode;
		private final Thread thread;

		SimulatedLifetimeServer() throws Exception {
			this(LifetimeServerMode.NORMAL);
		}

		SimulatedLifetimeServer(LifetimeServerMode mode) throws Exception {
			this.mode = mode;
			this.socket = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"));
			this.socket.setSoTimeout(30);
			this.thread = new Thread(this::serve, "SimLifetimeServer");
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
					if (req.getType() != MessageHeaderType.BindingRequest) {
						continue;
					}

					ResponseAddress ra = (ResponseAddress) req.getMessageAttribute(MessageAttributeType.ResponseAddress);
					ResponsePort rp = (ResponsePort) req.getMessageAttribute(MessageAttributeType.ResponsePort);
					if (ra == null && rp == null) {
						// Initial binding communication on initialSocket
						if (mode == LifetimeServerMode.INITIAL_ERROR) {
							MessageHeader err = new MessageHeader(MessageHeaderType.BindingErrorResponse);
							err.setTransactionID(req.getTransactionID());
							ErrorCode ec = new ErrorCode();
							ec.setResponseCode(500);
							err.addMessageAttribute(ec);
							byte[] out = err.getBytes();
							socket.send(new DatagramPacket(out, out.length, pkt.getAddress(), pkt.getPort()));
							continue;
						}
						MessageHeader resp = new MessageHeader(MessageHeaderType.BindingResponse);
						resp.setTransactionID(req.getTransactionID());
						if (mode == LifetimeServerMode.XOR_MAPPED_ONLY) {
							XorMappedAddress xma = new XorMappedAddress(req.getTransactionID());
							xma.setAddress(new Address(pkt.getAddress().getAddress()));
							xma.setPort(pkt.getPort());
							resp.addMessageAttribute(xma);
						} else if (mode != LifetimeServerMode.INITIAL_MISSING_MAPPED) {
							MappedAddress ma = new MappedAddress();
							ma.setAddress(new Address(pkt.getAddress().getAddress()));
							ma.setPort(pkt.getPort());
							resp.addMessageAttribute(ma);
						}
						byte[] out = resp.getBytes();
						socket.send(new DatagramPacket(out, out.length, pkt.getAddress(), pkt.getPort()));
					} else {
						// Probe from secondary socket with RESPONSE-ADDRESS or RESPONSE-PORT pointing to initialSocket
						int probeNum = responseAddressProbeCount.incrementAndGet();
						InetAddress targetIp = (ra != null) ? ra.getAddress().getInetAddress() : pkt.getAddress();
						int targetPort = (ra != null) ? ra.getPort() : rp.getPort();
						if (mode == LifetimeServerMode.PROBE_ERROR) {
							MessageHeader err = new MessageHeader(MessageHeaderType.BindingErrorResponse);
							err.setTransactionID(req.getTransactionID());
							ErrorCode ec = new ErrorCode();
							ec.setResponseCode(500);
							err.addMessageAttribute(ec);
							byte[] out = err.getBytes();
							socket.send(new DatagramPacket(out, out.length, targetIp, targetPort));
							continue;
						}
						boolean shouldRespond = (mode == LifetimeServerMode.ALWAYS_SUCCEED)
								|| (mode != LifetimeServerMode.ALWAYS_TIMEOUT && probeNum != 2);
						if (shouldRespond) {
							MessageHeader resp = new MessageHeader(MessageHeaderType.BindingResponse);
							resp.setTransactionID(req.getTransactionID());
							MappedAddress ma = new MappedAddress();
							ma.setAddress(new Address(targetIp.getAddress()));
							ma.setPort(targetPort);
							resp.addMessageAttribute(ma);
							byte[] out = resp.getBytes();
							socket.send(new DatagramPacket(out, out.length, targetIp, targetPort));
						}
					}
				} catch (SocketTimeoutException ste) {
					// continue
				} catch (Exception e) {
					// ignore on close
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

	@Test
	public void testBindingLifetimeBinarySearchAlgorithm() throws Exception {
		try (SimulatedLifetimeServer server = new SimulatedLifetimeServer()) {
			BindingLifetimeTest blt = new BindingLifetimeTest("127.0.0.1", server.getPort());
			// Use a small upper bound (4 ms -> initial midpoint 2 ms, then 3 ms -> converges)
			blt.setUpperBinarySearchLifetime(4);
			blt.setTimeout(30);
			try {
				blt.test();
				long deadline = System.currentTimeMillis() + 3000;
				while (!blt.isCompleted() && System.currentTimeMillis() < deadline) {
					Thread.sleep(15);
				}
				assertTrue(blt.isCompleted());
				assertEquals(2, blt.getLifetime());
			} finally {
				blt.close();
			}
		}
	}

	@Test
	public void testBindingLifetimeWithRfc5780ResponsePort() throws Exception {
		try (SimulatedLifetimeServer server = new SimulatedLifetimeServer()) {
			BindingLifetimeTest blt = new BindingLifetimeTest("127.0.0.1", server.getPort());
			blt.setUseResponsePort(true);
			assertTrue(blt.isUseResponsePort());
			blt.setUpperBinarySearchLifetime(4);
			blt.setTimeout(30);
			try {
				blt.test();
				long deadline = System.currentTimeMillis() + 3000;
				while (!blt.isCompleted() && System.currentTimeMillis() < deadline) {
					Thread.sleep(15);
				}
				assertTrue(blt.isCompleted());
				assertEquals(2, blt.getLifetime());
			} finally {
				blt.close();
			}
		}
	}

	@Test
	public void testBindingLifetimeErrorXorFallbackAndConvergenceBranches() throws Exception {
		// close() before test() must be safe
		BindingLifetimeTest unused = new BindingLifetimeTest("127.0.0.1", 3478);
		unused.close();

		// 1. Initial error response stops before scheduling timer
		try (SimulatedLifetimeServer server = new SimulatedLifetimeServer(LifetimeServerMode.INITIAL_ERROR)) {
			BindingLifetimeTest blt = new BindingLifetimeTest("127.0.0.1", server.getPort());
			blt.setTimeout(50);
			try {
				blt.test();
				assertFalse(blt.isCompleted());
				assertEquals(-1, blt.getLifetime());
			} finally {
				blt.close();
			}
		}

		// 2. Initial missing MAPPED-ADDRESS stops before scheduling timer
		try (SimulatedLifetimeServer server = new SimulatedLifetimeServer(LifetimeServerMode.INITIAL_MISSING_MAPPED)) {
			BindingLifetimeTest blt = new BindingLifetimeTest("127.0.0.1", server.getPort());
			blt.setTimeout(50);
			try {
				blt.test();
				assertFalse(blt.isCompleted());
				assertEquals(-1, blt.getLifetime());
			} finally {
				blt.close();
			}
		}

		// 3. XOR-MAPPED-ADDRESS fallback on initial response
		try (SimulatedLifetimeServer server = new SimulatedLifetimeServer(LifetimeServerMode.XOR_MAPPED_ONLY)) {
			BindingLifetimeTest blt = new BindingLifetimeTest("127.0.0.1", server.getPort());
			blt.setUpperBinarySearchLifetime(4);
			blt.setTimeout(30);
			try {
				blt.test();
				long deadline = System.currentTimeMillis() + 3000;
				while (!blt.isCompleted() && System.currentTimeMillis() < deadline) {
					Thread.sleep(15);
				}
				assertTrue(blt.isCompleted());
				assertEquals(2, blt.getLifetime());
			} finally {
				blt.close();
			}
		}

		// 4. ErrorCode during lifetimeQuery() stops cleanly
		try (SimulatedLifetimeServer server = new SimulatedLifetimeServer(LifetimeServerMode.PROBE_ERROR)) {
			BindingLifetimeTest blt = new BindingLifetimeTest("127.0.0.1", server.getPort());
			blt.setUpperBinarySearchLifetime(4);
			blt.setTimeout(50);
			try {
				blt.test();
				Thread.sleep(100);
				assertFalse(blt.isCompleted());
				assertEquals(-1, blt.getLifetime());
			} finally {
				blt.close();
			}
		}

		// 5. All probes time out -> timeout convergence branch
		try (SimulatedLifetimeServer server = new SimulatedLifetimeServer(LifetimeServerMode.ALWAYS_TIMEOUT)) {
			BindingLifetimeTest blt = new BindingLifetimeTest("127.0.0.1", server.getPort());
			blt.setUpperBinarySearchLifetime(4);
			blt.setTimeout(25);
			try {
				blt.test();
				long deadline = System.currentTimeMillis() + 3000;
				while (!blt.isCompleted() && System.currentTimeMillis() < deadline) {
					Thread.sleep(15);
				}
				assertTrue(blt.isCompleted());
				assertEquals(-1, blt.getLifetime());
			} finally {
				blt.close();
			}
		}

		// 6. All probes succeed -> success convergence branch
		try (SimulatedLifetimeServer server = new SimulatedLifetimeServer(LifetimeServerMode.ALWAYS_SUCCEED)) {
			BindingLifetimeTest blt = new BindingLifetimeTest("127.0.0.1", server.getPort());
			blt.setUpperBinarySearchLifetime(4);
			blt.setTimeout(25);
			try {
				blt.test();
				long deadline = System.currentTimeMillis() + 3000;
				while (!blt.isCompleted() && System.currentTimeMillis() < deadline) {
					Thread.sleep(15);
				}
				assertTrue(blt.isCompleted());
				assertEquals(3, blt.getLifetime());
			} finally {
				blt.close();
			}
		}
	}

	private static int[] findFourFreePorts(InetAddress bindAddr) throws Exception {
		int[] ports = new int[4];
		DatagramSocket[] temp = new DatagramSocket[4];
		try {
			for (int i = 0; i < 4; i++) {
				temp[i] = new DatagramSocket(0, bindAddr);
				ports[i] = temp[i].getLocalPort();
			}
		} finally {
			for (DatagramSocket s : temp) {
				if (s != null) {
					s.close();
				}
			}
		}
		return ports;
	}

	@Test
	public void testStunServerAllRequestModesAndErrorResponse() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");
		int[] ports = findFourFreePorts(loopback);
		StunServer server = new StunServer(ports[0], loopback, ports[1], loopback, ports[2], ports[3]);
		server.start();

		try (DatagramSocket clientSocket = new DatagramSocket(0, loopback);
				DatagramSocket responseTargetSocket = new DatagramSocket(0, loopback)) {
			clientSocket.setSoTimeout(1000);
			responseTargetSocket.setSoTimeout(1000);

			// 1. Standard BindingRequest (no change flags)
			MessageHeader req1 = new MessageHeader(MessageHeaderType.BindingRequest);
			req1.generateTransactionID();
			byte[] req1Bytes = req1.getBytes();
			clientSocket.send(new DatagramPacket(req1Bytes, req1Bytes.length, loopback, ports[0]));

			DatagramPacket recv1 = new DatagramPacket(new byte[512], 512);
			clientSocket.receive(recv1);
			assertEquals(ports[0], recv1.getPort());
			MessageHeader resp1 = MessageHeader.parseHeader(recv1.getData());
			resp1.parseAttributes(recv1.getData());
			assertEquals(MessageHeaderType.BindingResponse, resp1.getType());

			MappedAddress ma1 = (MappedAddress) resp1.getMessageAttribute(MessageAttributeType.MappedAddress);
			XorMappedAddress xma1 = (XorMappedAddress) resp1.getMessageAttribute(MessageAttributeType.XorMappedAddress);
			ChangedAddress ca1 = (ChangedAddress) resp1.getMessageAttribute(MessageAttributeType.ChangedAddress);
			OtherAddress oa1 = (OtherAddress) resp1.getMessageAttribute(MessageAttributeType.OtherAddress);
			SourceAddress sa1 = (SourceAddress) resp1.getMessageAttribute(MessageAttributeType.SourceAddress);
			ResponseOrigin ro1 = (ResponseOrigin) resp1.getMessageAttribute(MessageAttributeType.ResponseOrigin);

			// RFC 5389 Section 15.10: server identifies itself via SOFTWARE attribute
			Software sw1 = (Software) resp1.getMessageAttribute(MessageAttributeType.Software);
			assertNotNull(sw1);
			assertEquals(JstunVersion.SOFTWARE, sw1.getSoftware());
			assertTrue(sw1.getSoftware().startsWith("JSTUN/"));

			// RFC 5389 Section 15.5: FINGERPRINT attribute is present and valid as final attribute
			byte[] resp1Raw = new byte[recv1.getLength()];
			System.arraycopy(recv1.getData(), 0, resp1Raw, 0, resp1Raw.length);
			assertTrue(Fingerprint.verify(resp1Raw));
			assertNotNull(resp1.getMessageAttribute(MessageAttributeType.Fingerprint));

			assertNotNull(ma1);
			assertNotNull(xma1);
			assertNotNull(ca1);
			assertNotNull(oa1);
			assertNotNull(sa1);
			assertNotNull(ro1);
			assertEquals(clientSocket.getLocalPort(), ma1.getPort());
			assertEquals(clientSocket.getLocalPort(), xma1.getPort());
			assertEquals(ports[0], sa1.getPort());
			assertEquals(ports[0], ro1.getPort());
			assertEquals(ports[3], ca1.getPort());
			assertEquals(ports[3], oa1.getPort());

			// 2. ChangeRequest: changePort=true, changeIP=false -> response sent from ports[1]
			MessageHeader req2 = new MessageHeader(MessageHeaderType.BindingRequest);
			req2.generateTransactionID();
			ChangeRequest crPort = new ChangeRequest();
			crPort.setChangePort();
			req2.addMessageAttribute(crPort);
			byte[] req2Bytes = req2.getBytes();
			clientSocket.send(new DatagramPacket(req2Bytes, req2Bytes.length, loopback, ports[0]));

			DatagramPacket recv2 = new DatagramPacket(new byte[512], 512);
			clientSocket.receive(recv2);
			assertEquals(ports[1], recv2.getPort());

			// 3. ChangeRequest: changePort=false, changeIP=true -> response sent from ports[2]
			MessageHeader req3 = new MessageHeader(MessageHeaderType.BindingRequest);
			req3.generateTransactionID();
			ChangeRequest crIP = new ChangeRequest();
			crIP.setChangeIP();
			req3.addMessageAttribute(crIP);
			byte[] req3Bytes = req3.getBytes();
			clientSocket.send(new DatagramPacket(req3Bytes, req3Bytes.length, loopback, ports[0]));

			DatagramPacket recv3 = new DatagramPacket(new byte[512], 512);
			clientSocket.receive(recv3);
			assertEquals(ports[2], recv3.getPort());

			// 4. ChangeRequest: changePort=true, changeIP=true -> response sent from ports[3]
			MessageHeader req4 = new MessageHeader(MessageHeaderType.BindingRequest);
			req4.generateTransactionID();
			ChangeRequest crBoth = new ChangeRequest();
			crBoth.setChangeIP();
			crBoth.setChangePort();
			req4.addMessageAttribute(crBoth);
			byte[] req4Bytes = req4.getBytes();
			clientSocket.send(new DatagramPacket(req4Bytes, req4Bytes.length, loopback, ports[0]));

			DatagramPacket recv4 = new DatagramPacket(new byte[512], 512);
			clientSocket.receive(recv4);
			assertEquals(ports[3], recv4.getPort());

			// 5. RFC 5780 RESPONSE-PORT attribute -> response delivered to responseTargetSocket
			MessageHeader req5 = new MessageHeader(MessageHeaderType.BindingRequest);
			req5.generateTransactionID();
			req5.addMessageAttribute(new ResponsePort(responseTargetSocket.getLocalPort()));
			byte[] req5Bytes = req5.getBytes();
			clientSocket.send(new DatagramPacket(req5Bytes, req5Bytes.length, loopback, ports[0]));

			DatagramPacket recv5 = new DatagramPacket(new byte[512], 512);
			responseTargetSocket.receive(recv5);
			MessageHeader resp5 = MessageHeader.parseHeader(recv5.getData());
			resp5.parseAttributes(recv5.getData());
			assertTrue(resp5.equalTransactionID(req5));

			// 6. RFC 3489 RESPONSE-ADDRESS attribute -> response delivered to responseTargetSocket
			MessageHeader req6 = new MessageHeader(MessageHeaderType.BindingRequest);
			req6.generateTransactionID();
			ResponseAddress ra = new ResponseAddress();
			ra.setAddress(new Address("127.0.0.1"));
			ra.setPort(responseTargetSocket.getLocalPort());
			req6.addMessageAttribute(ra);
			byte[] req6Bytes = req6.getBytes();
			clientSocket.send(new DatagramPacket(req6Bytes, req6Bytes.length, loopback, ports[0]));

			DatagramPacket recv6 = new DatagramPacket(new byte[512], 512);
			responseTargetSocket.receive(recv6);
			MessageHeader resp6 = MessageHeader.parseHeader(recv6.getData());
			resp6.parseAttributes(recv6.getData());
			assertTrue(resp6.equalTransactionID(req6));

			// 7. Unknown comprehension-required attribute (0x0000 = DUMMY) -> BindingErrorResponse with UnknownAttribute
			byte[] rawHeader = req1.getBytes(); // 20-byte BindingRequest header
			byte[] packetWithUnknownMandatory = new byte[28];
			System.arraycopy(rawHeader, 0, packetWithUnknownMandatory, 0, 20);
			packetWithUnknownMandatory[2] = 0x00;
			packetWithUnknownMandatory[3] = 0x08; // 8-byte payload
			// Attribute type 0x0000 (DUMMY, <= 0x7fff so comprehension-required), length 4
			packetWithUnknownMandatory[20] = 0x00;
			packetWithUnknownMandatory[21] = 0x00;
			packetWithUnknownMandatory[22] = 0x00;
			packetWithUnknownMandatory[23] = 0x04;
			clientSocket.send(new DatagramPacket(packetWithUnknownMandatory, packetWithUnknownMandatory.length,
					loopback, ports[0]));

			DatagramPacket recv7 = new DatagramPacket(new byte[512], 512);
			clientSocket.receive(recv7);
			MessageHeader resp7 = MessageHeader.parseHeader(recv7.getData());
			resp7.parseAttributes(recv7.getData());
			assertEquals(MessageHeaderType.BindingErrorResponse, resp7.getType());
			UnknownAttribute ua = (UnknownAttribute) resp7.getMessageAttribute(MessageAttributeType.UnknownAttribute);
			assertNotNull(ua);
			ErrorCode ec7 = (ErrorCode) resp7.getMessageAttribute(MessageAttributeType.ErrorCode);
			assertNotNull(ec7);
			assertEquals(420, ec7.getResponseCode());
			byte[] resp7Raw = new byte[recv7.getLength()];
			System.arraycopy(recv7.getData(), 0, resp7Raw, 0, resp7Raw.length);
			assertTrue(Fingerprint.verify(resp7Raw));

			// 8. Request with invalid FINGERPRINT -> discarded by server (RFC 5389 §15.5)
			MessageHeader req8 = new MessageHeader(MessageHeaderType.BindingRequest);
			req8.generateTransactionID();
			byte[] req8Bytes = req8.getBytesWithFingerprint();
			req8Bytes[req8Bytes.length - 1] ^= 0x01; // corrupt fingerprint CRC
			clientSocket.send(new DatagramPacket(req8Bytes, req8Bytes.length, loopback, ports[0]));
			clientSocket.setSoTimeout(150);
			DatagramPacket recv8 = new DatagramPacket(new byte[512], 512);
			org.junit.jupiter.api.Assertions.assertThrows(SocketTimeoutException.class,
					() -> clientSocket.receive(recv8));

			// 9. Jumbo frame BindingRequest with PADDING (~3000 bytes) -> server echoes PADDING
			clientSocket.setSoTimeout(1000);
			MessageHeader req9 = new MessageHeader(MessageHeaderType.BindingRequest);
			req9.generateTransactionID();
			req9.addMessageAttribute(new Padding(2900));
			byte[] req9Bytes = req9.getBytesWithFingerprint();
			assertTrue(req9Bytes.length > 2900);
			clientSocket.send(new DatagramPacket(req9Bytes, req9Bytes.length, loopback, ports[0]));

			DatagramPacket recv9 = new DatagramPacket(new byte[10240], 10240);
			clientSocket.receive(recv9);
			byte[] resp9Raw = new byte[recv9.getLength()];
			System.arraycopy(recv9.getData(), 0, resp9Raw, 0, resp9Raw.length);
			assertTrue(Fingerprint.verify(resp9Raw));
			MessageHeader resp9 = MessageHeader.parseHeader(resp9Raw);
			resp9.parseAttributes(resp9Raw);
			assertEquals(MessageHeaderType.BindingResponse, resp9.getType());
			assertNotNull(resp9.getMessageAttribute(MessageAttributeType.Padding));
			assertTrue(resp9Raw.length >= 2900 && resp9Raw.length <= req9Bytes.length);

			// 10. Malformed/runtime-triggering packets must not kill StunServer receiver thread
			byte[] truncatedAttrPacket = new byte[24];
			System.arraycopy(rawHeader, 0, truncatedAttrPacket, 0, 20);
			truncatedAttrPacket[2] = 0x00;
			truncatedAttrPacket[3] = 0x04; // payload length 4
			truncatedAttrPacket[20] = 0x00;
			truncatedAttrPacket[21] = 0x01; // MAPPED-ADDRESS
			truncatedAttrPacket[22] = 0x00;
			truncatedAttrPacket[23] = 0x20; // claims 32 bytes when only 0 remain
			clientSocket.send(new DatagramPacket(truncatedAttrPacket, truncatedAttrPacket.length, loopback, ports[0]));

			// Follow-up valid BindingRequest must still succeed
			MessageHeader req10 = new MessageHeader(MessageHeaderType.BindingRequest);
			req10.generateTransactionID();
			byte[] req10Bytes = req10.getBytesWithFingerprint();
			clientSocket.send(new DatagramPacket(req10Bytes, req10Bytes.length, loopback, ports[0]));

			DatagramPacket recv10 = new DatagramPacket(new byte[512], 512);
			clientSocket.receive(recv10);
			MessageHeader resp10 = MessageHeader.parseHeader(recv10.getData());
			resp10.parseAttributes(recv10.getData());
			assertEquals(MessageHeaderType.BindingResponse, resp10.getType());
			assertTrue(resp10.equalTransactionID(req10));

			// Stop server so receiver threads finish updating stats before assertions
			server.stop();
			server.stop(); // idempotent

			// Verify server observability counters
			StunServer.StunServerStats stats = server.getStats();
			assertTrue(stats.getPacketsReceived() >= 10);
			assertTrue(stats.getBytesReceived() > 0);
			assertTrue(stats.getBindingRequests() >= 8);
			assertEquals(3, stats.getChangeRequests());
			assertEquals(1, stats.getResponsePortRequests());
			assertEquals(1, stats.getResponseAddressRequests());
			assertEquals(1, stats.getPaddingRequests());
			assertTrue(stats.getBindingResponsesSent() >= 8);
			assertEquals(1, stats.getBindingErrorsSent());
			assertEquals(1, stats.getDroppedInvalidFingerprint());
			assertEquals(1, stats.getDroppedParseError());
			assertTrue(stats.getBytesSent() > 0);
			assertTrue(stats.formatSummary().contains("packetsIn="));
		} finally {
			server.stop();
		}
	}

	@Test
	public void testStunServerEdgeCasesPaddingBoundsAndParseErrors() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");
		int[] ports = findFourFreePorts(loopback);
		StunServer server = new StunServer(ports[0], loopback, ports[1], loopback, ports[2], ports[3]);
		server.setStatsIntervalSeconds(0);
		server.start();

		try (DatagramSocket client = new DatagramSocket(0, loopback)) {
			client.setSoTimeout(1000);
			client.setReceiveBufferSize(65536);
			client.setSendBufferSize(65536);

			// 1. Unsupported STUN header type (0x9999) -> MessageHeaderParsingException counted
			byte[] badHeader = new byte[20];
			badHeader[0] = (byte) 0x99;
			badHeader[1] = (byte) 0x99;
			client.send(new DatagramPacket(badHeader, badHeader.length, loopback, ports[0]));

			// 2. Malformed ChangeRequest attribute (length 1 instead of 4) -> MessageAttributeParsingException counted
			MessageHeader validHdr = new MessageHeader(MessageHeaderType.BindingRequest);
			validHdr.generateTransactionID();
			byte[] badAttr = new byte[28];
			System.arraycopy(validHdr.getBytes(), 0, badAttr, 0, 20);
			badAttr[2] = 0x00;
			badAttr[3] = 0x08; // payload 8 bytes
			badAttr[20] = 0x00;
			badAttr[21] = 0x03; // CHANGE-REQUEST
			badAttr[22] = 0x00;
			badAttr[23] = 0x01; // invalid length 1 (< 4)
			client.send(new DatagramPacket(badAttr, badAttr.length, loopback, ports[0]));

			// 3. Small PADDING (4 bytes) -> rawEchoPad < 0, response succeeds without echoing PADDING
			MessageHeader smallPadReq = new MessageHeader(MessageHeaderType.BindingRequest);
			smallPadReq.generateTransactionID();
			smallPadReq.addMessageAttribute(new Padding(4));
			byte[] smallPadBytes = smallPadReq.getBytesWithFingerprint();
			client.send(new DatagramPacket(smallPadBytes, smallPadBytes.length, loopback, ports[0]));

			DatagramPacket recvSmall = new DatagramPacket(new byte[512], 512);
			client.receive(recvSmall);
			byte[] smallRespRaw = java.util.Arrays.copyOf(recvSmall.getData(), recvSmall.getLength());
			assertTrue(Fingerprint.verify(smallRespRaw));
			MessageHeader smallResp = MessageHeader.parseHeader(smallRespRaw);
			smallResp.parseAttributes(smallRespRaw);
			assertEquals(MessageHeaderType.BindingResponse, smallResp.getType());
			assertTrue(smallResp.equalTransactionID(smallPadReq));
			assertNull(smallResp.getMessageAttribute(MessageAttributeType.Padding));

			// 4. Oversized PADDING (9400 bytes) > MAX_ECHO_PACKET_SIZE (9216) -> echoed response capped <= 9216
			MessageHeader hugePadReq = new MessageHeader(MessageHeaderType.BindingRequest);
			hugePadReq.generateTransactionID();
			hugePadReq.addMessageAttribute(new Padding(9400));
			byte[] hugePadBytes = hugePadReq.getBytesWithFingerprint();
			assertTrue(hugePadBytes.length > 9216);
			client.send(new DatagramPacket(hugePadBytes, hugePadBytes.length, loopback, ports[0]));

			DatagramPacket recvHuge = new DatagramPacket(new byte[10240], 10240);
			client.receive(recvHuge);
			byte[] hugeRespRaw = java.util.Arrays.copyOf(recvHuge.getData(), recvHuge.getLength());
			assertTrue(Fingerprint.verify(hugeRespRaw));
			assertTrue(hugeRespRaw.length <= 9216, "Echoed response must be capped at 9216, got " + hugeRespRaw.length);
			assertTrue(hugeRespRaw.length >= 9000);
			MessageHeader hugeResp = MessageHeader.parseHeader(hugeRespRaw);
			hugeResp.parseAttributes(hugeRespRaw);
			assertNotNull(hugeResp.getMessageAttribute(MessageAttributeType.Padding));

			server.stop();

			// Verify both parse errors and both padding requests were tracked
			StunServer.StunServerStats stats = server.getStats();
			assertEquals(2, stats.getDroppedParseError());
			assertEquals(2, stats.getPaddingRequests());
			assertEquals(2, stats.getBindingResponsesSent());
		} finally {
			server.stop();
		}
	}

	@Test
	public void testStunServerDualStackSimultaneousIpv4AndIpv6AndIpv6Only() throws Exception {
		InetAddress ipv4 = InetAddress.getByName("127.0.0.1");
		InetAddress ipv6;
		try {
			ipv6 = InetAddress.getByName("::1");
			try (DatagramSocket probe = new DatagramSocket(0, ipv6)) {
				assertTrue(probe.getLocalPort() > 0);
			}
		} catch (Exception e) {
			assumeTrue(false, "IPv6 loopback ::1 not available in this environment");
			return;
		}

		// 1. IPv6-only via optional-family constructor (null IPv4 pair)
		int[] v6OnlyPorts = findFourFreePorts(ipv6);
		StunServer v6Only = new StunServer(
				0, null, 0, null, 0, 0,
				v6OnlyPorts[0], ipv6, v6OnlyPorts[1], ipv6, v6OnlyPorts[2], v6OnlyPorts[3]);
		v6Only.setStatsIntervalSeconds(0);
		assertFalse(v6Only.isIpv4Enabled());
		assertTrue(v6Only.isIpv6Enabled());
		v6Only.start();
		try (DatagramSocket v6Client = new DatagramSocket(0, ipv6)) {
			v6Client.setSoTimeout(1000);
			MessageHeader req = new MessageHeader(MessageHeaderType.BindingRequest);
			req.generateTransactionID();
			byte[] reqBytes = req.getBytesWithFingerprint();
			v6Client.send(new DatagramPacket(reqBytes, reqBytes.length, ipv6, v6OnlyPorts[0]));

			DatagramPacket recv = new DatagramPacket(new byte[512], 512);
			v6Client.receive(recv);
			assertEquals(v6OnlyPorts[0], recv.getPort());
			MessageHeader resp = MessageHeader.parseHeader(recv.getData());
			resp.parseAttributes(recv.getData());
			XorMappedAddress xma = (XorMappedAddress) resp.getMessageAttribute(MessageAttributeType.XorMappedAddress);
			assertNotNull(xma);
			assertTrue(xma.getAddress().getInetAddress() instanceof Inet6Address);
			assertEquals(v6Client.getLocalPort(), xma.getPort());
		} finally {
			v6Only.stop();
		}

		// 2. Simultaneous dual-stack (IPv4 + IPv6 in a single StunServer instance)
		int[] v4Ports = findFourFreePorts(ipv4);
		int[] v6Ports = findFourFreePorts(ipv6);
		StunServer dualStack = new StunServer(
				v4Ports[0], ipv4, v4Ports[1], ipv4, v4Ports[2], v4Ports[3],
				v6Ports[0], ipv6, v6Ports[1], ipv6, v6Ports[2], v6Ports[3]);
		dualStack.setStatsIntervalSeconds(0);
		assertTrue(dualStack.isIpv4Enabled());
		assertTrue(dualStack.isIpv6Enabled());
		dualStack.start();

		try (DatagramSocket v4Client = new DatagramSocket(0, ipv4);
				DatagramSocket v6Client = new DatagramSocket(0, ipv6)) {
			v4Client.setSoTimeout(1000);
			v6Client.setSoTimeout(1000);

			// IPv4 standard BindingRequest + CHANGE-REQUEST (IP + port) stays inside IPv4 group
			MessageHeader v4Req = new MessageHeader(MessageHeaderType.BindingRequest);
			v4Req.generateTransactionID();
			byte[] v4Bytes = v4Req.getBytesWithFingerprint();
			v4Client.send(new DatagramPacket(v4Bytes, v4Bytes.length, ipv4, v4Ports[0]));

			DatagramPacket v4Recv = new DatagramPacket(new byte[512], 512);
			v4Client.receive(v4Recv);
			assertEquals(v4Ports[0], v4Recv.getPort());
			MessageHeader v4Resp = MessageHeader.parseHeader(v4Recv.getData());
			v4Resp.parseAttributes(v4Recv.getData());
			XorMappedAddress v4Xma = (XorMappedAddress) v4Resp.getMessageAttribute(MessageAttributeType.XorMappedAddress);
			OtherAddress v4Oa = (OtherAddress) v4Resp.getMessageAttribute(MessageAttributeType.OtherAddress);
			assertNotNull(v4Xma);
			assertNotNull(v4Oa);
			assertFalse(v4Xma.getAddress().getInetAddress() instanceof Inet6Address);
			assertFalse(v4Oa.getAddress().getInetAddress() instanceof Inet6Address);
			assertEquals(v4Ports[3], v4Oa.getPort());

			MessageHeader v4CrReq = new MessageHeader(MessageHeaderType.BindingRequest);
			v4CrReq.generateTransactionID();
			ChangeRequest v4Cr = new ChangeRequest();
			v4Cr.setChangeIP();
			v4Cr.setChangePort();
			v4CrReq.addMessageAttribute(v4Cr);
			byte[] v4CrBytes = v4CrReq.getBytesWithFingerprint();
			v4Client.send(new DatagramPacket(v4CrBytes, v4CrBytes.length, ipv4, v4Ports[0]));

			DatagramPacket v4CrRecv = new DatagramPacket(new byte[512], 512);
			v4Client.receive(v4CrRecv);
			assertEquals(v4Ports[3], v4CrRecv.getPort());

			// IPv6 standard BindingRequest + CHANGE-REQUEST (IP + port) stays inside IPv6 group
			MessageHeader v6Req = new MessageHeader(MessageHeaderType.BindingRequest);
			v6Req.generateTransactionID();
			byte[] v6Bytes = v6Req.getBytesWithFingerprint();
			v6Client.send(new DatagramPacket(v6Bytes, v6Bytes.length, ipv6, v6Ports[0]));

			DatagramPacket v6Recv = new DatagramPacket(new byte[512], 512);
			v6Client.receive(v6Recv);
			assertEquals(v6Ports[0], v6Recv.getPort());
			assertTrue(v6Recv.getAddress() instanceof Inet6Address);
			MessageHeader v6Resp = MessageHeader.parseHeader(v6Recv.getData());
			v6Resp.parseAttributes(v6Recv.getData());
			XorMappedAddress v6Xma = (XorMappedAddress) v6Resp.getMessageAttribute(MessageAttributeType.XorMappedAddress);
			OtherAddress v6Oa = (OtherAddress) v6Resp.getMessageAttribute(MessageAttributeType.OtherAddress);
			ResponseOrigin v6Ro = (ResponseOrigin) v6Resp.getMessageAttribute(MessageAttributeType.ResponseOrigin);
			assertNotNull(v6Xma);
			assertNotNull(v6Oa);
			assertNotNull(v6Ro);
			assertTrue(v6Xma.getAddress().getInetAddress() instanceof Inet6Address);
			assertTrue(v6Oa.getAddress().getInetAddress() instanceof Inet6Address);
			assertTrue(v6Ro.getAddress().getInetAddress() instanceof Inet6Address);
			assertEquals(v6Client.getLocalPort(), v6Xma.getPort());
			assertEquals(v6Ports[0], v6Ro.getPort());
			assertEquals(v6Ports[3], v6Oa.getPort());

			MessageHeader v6CrReq = new MessageHeader(MessageHeaderType.BindingRequest);
			v6CrReq.generateTransactionID();
			ChangeRequest v6Cr = new ChangeRequest();
			v6Cr.setChangeIP();
			v6Cr.setChangePort();
			v6CrReq.addMessageAttribute(v6Cr);
			byte[] v6CrBytes = v6CrReq.getBytesWithFingerprint();
			v6Client.send(new DatagramPacket(v6CrBytes, v6CrBytes.length, ipv6, v6Ports[0]));

			DatagramPacket v6CrRecv = new DatagramPacket(new byte[512], 512);
			v6Client.receive(v6CrRecv);
			assertEquals(v6Ports[3], v6CrRecv.getPort());
			assertTrue(v6CrRecv.getAddress() instanceof Inet6Address);

			dualStack.stop();

			// Shared stats track both IPv4 and IPv6 requests
			assertEquals(4, dualStack.getStats().getBindingRequests());
			assertEquals(4, dualStack.getStats().getBindingResponsesSent());
			assertEquals(2, dualStack.getStats().getChangeRequests());
		} finally {
			dualStack.stop();
		}
	}
}
