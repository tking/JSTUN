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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.attribute.ChangeRequest;
import de.javawi.jstun.attribute.ChangedAddress;
import de.javawi.jstun.attribute.ErrorCode;
import de.javawi.jstun.attribute.MappedAddress;
import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.attribute.OtherAddress;
import de.javawi.jstun.attribute.XorMappedAddress;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.util.Address;

/**
 * Tests the RFC 3489 Section 10.1 NAT & Firewall discovery algorithm implemented
 * in {@link DiscoveryTest} and {@link FastDiscoveryTest} across all decision tree branches.
 */
public class Rfc3489DiscoveryAlgorithmTest {

	enum SimulatedScenario {
		BLOCKED_UDP,
		ERROR_RESPONSE,
		INCOMPLETE_RESPONSE,
		OPEN_ACCESS,
		SYMMETRIC_UDP_FIREWALL,
		FULL_CONE_NAT,
		SYMMETRIC_NAT,
		RESTRICTED_CONE_NAT,
		PORT_RESTRICTED_CONE_NAT,
		RFC5389_XOR_AND_OTHER_ONLY_FULL_CONE
	}

	static class SimulatedRfc3489Server implements AutoCloseable {
		private final DatagramSocket primarySocket;
		private final DatagramSocket alternateSocket;
		private final AtomicBoolean running = new AtomicBoolean(true);
		private final Thread primaryThread;
		private final Thread alternateThread;
		private final SimulatedScenario scenario;

		SimulatedRfc3489Server(SimulatedScenario scenario) throws Exception {
			this.scenario = scenario;
			InetAddress loopback = InetAddress.getByName("127.0.0.1");
			this.primarySocket = new DatagramSocket(0, loopback);
			this.alternateSocket = new DatagramSocket(0, loopback);
			this.primarySocket.setSoTimeout(50);
			this.alternateSocket.setSoTimeout(50);

			this.primaryThread = new Thread(() -> serve(primarySocket, true), "SimStun-Primary");
			this.alternateThread = new Thread(() -> serve(alternateSocket, false), "SimStun-Alt");
			this.primaryThread.setDaemon(true);
			this.alternateThread.setDaemon(true);
			this.primaryThread.start();
			this.alternateThread.start();
		}

		int getPrimaryPort() {
			return primarySocket.getLocalPort();
		}

		private void serve(DatagramSocket sock, boolean isPrimary) {
			byte[] buf = new byte[512];
			while (running.get() && !sock.isClosed()) {
				try {
					DatagramPacket pkt = new DatagramPacket(buf, buf.length);
					sock.receive(pkt);
					if (scenario == SimulatedScenario.BLOCKED_UDP) {
						continue;
					}

					MessageHeader req = MessageHeader.parseHeader(pkt.getData());
					req.parseAttributes(pkt.getData());
					if (req.getType() != MessageHeaderType.BindingRequest) {
						continue;
					}

					ChangeRequest cr = (ChangeRequest) req.getMessageAttribute(MessageAttributeType.ChangeRequest);
					boolean changeIP = (cr != null && cr.isChangeIP());
					boolean changePort = (cr != null && cr.isChangePort());

					if (scenario == SimulatedScenario.ERROR_RESPONSE) {
						MessageHeader errResp = new MessageHeader(MessageHeaderType.BindingErrorResponse);
						errResp.setTransactionID(req.getTransactionID());
						ErrorCode ec = new ErrorCode();
						ec.setResponseCode(500);
						errResp.addMessageAttribute(ec);
						sendPacket(sock, pkt.getAddress(), pkt.getPort(), errResp.getBytes());
						continue;
					}

					if (scenario == SimulatedScenario.INCOMPLETE_RESPONSE) {
						MessageHeader resp = new MessageHeader(MessageHeaderType.BindingResponse);
						resp.setTransactionID(req.getTransactionID());
						// Intentionally omit MAPPED-ADDRESS and CHANGED-ADDRESS
						sendPacket(sock, pkt.getAddress(), pkt.getPort(), resp.getBytes());
						continue;
					}

					// Test II: changeIP && changePort
					if (changeIP && changePort) {
						if (scenario == SimulatedScenario.OPEN_ACCESS
								|| scenario == SimulatedScenario.FULL_CONE_NAT
								|| scenario == SimulatedScenario.RFC5389_XOR_AND_OTHER_ONLY_FULL_CONE) {
							MessageHeader resp = buildBindingResponse(req, pkt, isPrimary);
							sendPacket(alternateSocket, pkt.getAddress(), pkt.getPort(), resp.getBytes());
						}
						// For SYMMETRIC_UDP_FIREWALL, SYMMETRIC_NAT, RESTRICTED_CONE_NAT, PORT_RESTRICTED_CONE_NAT: drop Test II
						continue;
					}

					// Test III: !changeIP && changePort
					if (!changeIP && changePort) {
						if (scenario == SimulatedScenario.RESTRICTED_CONE_NAT) {
							MessageHeader resp = buildBindingResponse(req, pkt, isPrimary);
							sendPacket(alternateSocket, pkt.getAddress(), pkt.getPort(), resp.getBytes());
						}
						// For PORT_RESTRICTED_CONE_NAT: drop Test III
						continue;
					}

					// Test I (isPrimary == true) or Test I Redo (isPrimary == false)
					MessageHeader resp = buildBindingResponse(req, pkt, isPrimary);
					sendPacket(sock, pkt.getAddress(), pkt.getPort(), resp.getBytes());
				} catch (SocketTimeoutException ste) {
					// continue loop
				} catch (Exception e) {
					if (running.get()) {
						// ignore transient close exceptions
					}
				}
			}
		}

		private MessageHeader buildBindingResponse(MessageHeader req, DatagramPacket pkt, boolean isPrimary)
				throws Exception {
			MessageHeader resp = new MessageHeader(MessageHeaderType.BindingResponse);
			resp.setTransactionID(req.getTransactionID());

			Address mappedAddr;
			int mappedPort;
			if (scenario == SimulatedScenario.OPEN_ACCESS || scenario == SimulatedScenario.SYMMETRIC_UDP_FIREWALL) {
				// No NAT translation: return client's real local IP and port
				mappedAddr = new Address(pkt.getAddress().getAddress());
				mappedPort = pkt.getPort();
			} else if (scenario == SimulatedScenario.SYMMETRIC_NAT && !isPrimary) {
				// Test I Redo on alternate destination gets a DIFFERENT public port
				mappedAddr = new Address("203.0.113.10");
				mappedPort = 50002;
			} else {
				// Standard NAT translation
				mappedAddr = new Address("203.0.113.10");
				mappedPort = 50001;
			}

			if (scenario == SimulatedScenario.RFC5389_XOR_AND_OTHER_ONLY_FULL_CONE) {
				XorMappedAddress xma = new XorMappedAddress(req.getTransactionID());
				xma.setAddress(mappedAddr);
				xma.setPort(mappedPort);
				resp.addMessageAttribute(xma);

				OtherAddress oa = new OtherAddress();
				oa.setAddress(new Address("127.0.0.1"));
				oa.setPort(alternateSocket.getLocalPort());
				resp.addMessageAttribute(oa);
			} else {
				MappedAddress ma = new MappedAddress();
				ma.setAddress(mappedAddr);
				ma.setPort(mappedPort);
				resp.addMessageAttribute(ma);

				ChangedAddress ca = new ChangedAddress();
				ca.setAddress(new Address("127.0.0.1"));
				ca.setPort(alternateSocket.getLocalPort());
				resp.addMessageAttribute(ca);
			}
			return resp;
		}

		private void sendPacket(DatagramSocket sender, InetAddress addr, int port, byte[] bytes) throws Exception {
			DatagramPacket out = new DatagramPacket(bytes, bytes.length, addr, port);
			sender.send(out);
		}

		@Override
		public void close() throws Exception {
			running.set(false);
			primarySocket.close();
			alternateSocket.close();
			primaryThread.join(500);
			alternateThread.join(500);
		}
	}

	private DiscoveryInfo runDiscoveryTest(SimulatedScenario scenario) throws Exception {
		try (SimulatedRfc3489Server server = new SimulatedRfc3489Server(scenario)) {
			DiscoveryTest dt = new DiscoveryTest(InetAddress.getByName("127.0.0.1"), "127.0.0.1",
					server.getPrimaryPort());
			dt.setTimeoutInitValue(40);
			dt.setMaxWaitTimeMs(80);
			return dt.test();
		}
	}

	private DiscoveryInfo runFastDiscoveryTest(SimulatedScenario scenario) throws Exception {
		try (SimulatedRfc3489Server server = new SimulatedRfc3489Server(scenario)) {
			FastDiscoveryTest fdt = new FastDiscoveryTest(InetAddress.getByName("127.0.0.1"), "127.0.0.1",
					server.getPrimaryPort());
			fdt.setTimeoutInitValue(40);
			fdt.setMaxWaitTimeMs(80);
			return fdt.test();
		}
	}

	@Test
	public void testDiscoveryBlockedUDP() throws Exception {
		DiscoveryInfo di = runDiscoveryTest(SimulatedScenario.BLOCKED_UDP);
		assertTrue(di.isBlockedUDP());
		assertFalse(di.isOpenAccess());
		assertTrue(di.toString().contains("Firewall blocks UDP"));
	}

	@Test
	public void testDiscoveryServerError() throws Exception {
		DiscoveryInfo di = runDiscoveryTest(SimulatedScenario.ERROR_RESPONSE);
		assertTrue(di.isError());
		assertTrue(di.toString().contains("500"));
	}

	@Test
	public void testDiscoveryIncompleteResponseError700() throws Exception {
		DiscoveryInfo di = runDiscoveryTest(SimulatedScenario.INCOMPLETE_RESPONSE);
		assertTrue(di.isError());
		assertTrue(di.toString().contains("700"));
	}

	@Test
	public void testDiscoveryOpenAccess() throws Exception {
		DiscoveryInfo di = runDiscoveryTest(SimulatedScenario.OPEN_ACCESS);
		assertTrue(di.isOpenAccess());
		assertFalse(di.isFullCone());
		assertTrue(di.toString().contains("Open access to the Internet"));
	}

	@Test
	public void testDiscoverySymmetricUDPFirewall() throws Exception {
		DiscoveryInfo di = runDiscoveryTest(SimulatedScenario.SYMMETRIC_UDP_FIREWALL);
		assertTrue(di.isSymmetricUDPFirewall());
		assertFalse(di.isOpenAccess());
		assertTrue(di.toString().contains("Symmetric UDP Firewall"));
	}

	@Test
	public void testDiscoveryFullConeNat() throws Exception {
		DiscoveryInfo di = runDiscoveryTest(SimulatedScenario.FULL_CONE_NAT);
		assertTrue(di.isFullCone());
		assertEquals(InetAddress.getByName("203.0.113.10"), di.getPublicIP());
		assertEquals(50001, di.getPublicPort());
		assertTrue(di.toString().contains("Full Cone NAT"));
	}

	@Test
	public void testDiscoverySymmetricNat() throws Exception {
		DiscoveryInfo di = runDiscoveryTest(SimulatedScenario.SYMMETRIC_NAT);
		assertTrue(di.isSymmetric());
		assertFalse(di.isRestrictedCone());
		assertFalse(di.isPortRestrictedCone());
		assertTrue(di.toString().contains("Symmetric Cone NAT"));
	}

	@Test
	public void testDiscoveryRestrictedConeNat() throws Exception {
		DiscoveryInfo di = runDiscoveryTest(SimulatedScenario.RESTRICTED_CONE_NAT);
		assertTrue(di.isRestrictedCone());
		assertFalse(di.isPortRestrictedCone());
		assertTrue(di.toString().contains("Restricted Cone NAT"));
	}

	@Test
	public void testDiscoveryPortRestrictedConeNat() throws Exception {
		DiscoveryInfo di = runDiscoveryTest(SimulatedScenario.PORT_RESTRICTED_CONE_NAT);
		assertTrue(di.isPortRestrictedCone());
		assertFalse(di.isRestrictedCone());
		assertTrue(di.toString().contains("Port restricted Cone NAT"));
	}

	@Test
	public void testDiscoveryWithRfc5389XorMappedAddressAndRfc5780OtherAddressOnly() throws Exception {
		DiscoveryInfo di = runDiscoveryTest(SimulatedScenario.RFC5389_XOR_AND_OTHER_ONLY_FULL_CONE);
		assertTrue(di.isFullCone());
		assertNotNull(di.getPublicIP());
		assertEquals(InetAddress.getByName("203.0.113.10"), di.getPublicIP());
		assertEquals(50001, di.getPublicPort());
	}

	@Test
	public void testFastDiscoveryAllScenarios() throws Exception {
		assertTrue(runFastDiscoveryTest(SimulatedScenario.BLOCKED_UDP).isBlockedUDP());
		assertTrue(runFastDiscoveryTest(SimulatedScenario.OPEN_ACCESS).isOpenAccess());
		assertTrue(runFastDiscoveryTest(SimulatedScenario.SYMMETRIC_UDP_FIREWALL).isSymmetricUDPFirewall());
		assertTrue(runFastDiscoveryTest(SimulatedScenario.FULL_CONE_NAT).isFullCone());
		assertTrue(runFastDiscoveryTest(SimulatedScenario.SYMMETRIC_NAT).isSymmetric());
		assertTrue(runFastDiscoveryTest(SimulatedScenario.RESTRICTED_CONE_NAT).isRestrictedCone());
		assertTrue(runFastDiscoveryTest(SimulatedScenario.PORT_RESTRICTED_CONE_NAT).isPortRestrictedCone());
	}
}
