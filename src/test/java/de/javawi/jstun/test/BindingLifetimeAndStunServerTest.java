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
import de.javawi.jstun.attribute.MappedAddress;
import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.attribute.OtherAddress;
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
					if (ra == null) {
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
						// Probe from secondary socket with RESPONSE-ADDRESS pointing to initialSocket
						int probeNum = responseAddressProbeCount.incrementAndGet();
						// Probe 1 succeeds (raises lower bound), Probe 2 times out (lowers upper bound), Probe 3+ succeeds
						if (probeNum != 2) {
							MessageHeader resp = new MessageHeader(MessageHeaderType.BindingResponse);
							resp.setTransactionID(req.getTransactionID());
							MappedAddress ma = new MappedAddress();
							ma.setAddress(ra.getAddress());
							ma.setPort(ra.getPort());
							resp.addMessageAttribute(ma);
							byte[] out = resp.getBytes();
							socket.send(new DatagramPacket(out, out.length,
									ra.getAddress().getInetAddress(), ra.getPort()));
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
		} finally {
			server.stop();
		}
	}
}
