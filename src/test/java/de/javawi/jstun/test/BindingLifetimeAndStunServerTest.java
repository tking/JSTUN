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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
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

	/**
	 * Simulated STUN server for BindingLifetimeTest that allows the first N
	 * RESPONSE-ADDRESS probes to succeed and drops subsequent probes (or vice versa)
	 * to exercise both halves of the binary search algorithm.
	 */
	static class SimulatedLifetimeServer implements AutoCloseable {
		private final DatagramSocket socket;
		private final AtomicBoolean running = new AtomicBoolean(true);
		private final AtomicInteger responseAddressProbeCount = new AtomicInteger(0);
		private final Thread thread;

		SimulatedLifetimeServer() throws Exception {
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
						MessageHeader resp = new MessageHeader(MessageHeaderType.BindingResponse);
						resp.setTransactionID(req.getTransactionID());
						MappedAddress ma = new MappedAddress();
						ma.setAddress(new Address(pkt.getAddress().getAddress()));
						ma.setPort(pkt.getPort());
						resp.addMessageAttribute(ma);
						byte[] out = resp.getBytes();
						socket.send(new DatagramPacket(out, out.length, pkt.getAddress(), pkt.getPort()));
					} else {
						// Probe from secondary socket with RESPONSE-ADDRESS or RESPONSE-PORT pointing to initialSocket
						int probeNum = responseAddressProbeCount.incrementAndGet();
						// Probe 1 succeeds (raises lower bound), Probe 2 times out (lowers upper bound), Probe 3+ succeeds
						if (probeNum != 2) {
							InetAddress targetIp = (ra != null) ? ra.getAddress().getInetAddress() : pkt.getAddress();
							int targetPort = (ra != null) ? ra.getPort() : rp.getPort();
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
			server.stop(); // idempotent
		}
	}
}
