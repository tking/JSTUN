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
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.attribute.ChangeRequest;
import de.javawi.jstun.attribute.ErrorCode;
import de.javawi.jstun.attribute.MappedAddress;
import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.attribute.OtherAddress;
import de.javawi.jstun.attribute.Padding;
import de.javawi.jstun.attribute.ResponseOrigin;
import de.javawi.jstun.attribute.ResponsePort;
import de.javawi.jstun.attribute.XorMappedAddress;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.test.DiscoveryInfo.FilteringBehavior;
import de.javawi.jstun.test.DiscoveryInfo.MappingBehavior;
import de.javawi.jstun.util.Address;

/**
 * Tests RFC 5780 attributes and the full NAT Behavior Discovery algorithm
 * ({@link NatBehaviorDiscoveryTest}) across Section 4.3 (Mapping Behavior Tests I, II, III)
 * and Section 4.4 (Filtering Behavior Tests II, III).
 */
public class Rfc5780AttributesAndDiscoveryTest {

	static class SimulatedRfc5780Server implements AutoCloseable {
		private final DatagramSocket primarySocket;
		private final DatagramSocket alternateSocket;
		private final AtomicBoolean running = new AtomicBoolean(true);
		private volatile byte[] firstPrimaryTxId = null;
		private final Thread primaryThread;
		private final Thread alternateThread;

		private final boolean dropAll;
		private final int errorCode;
		private final boolean omitMappedAddress;
		private final MappingBehavior targetMapping;
		private final FilteringBehavior targetFiltering;

		SimulatedRfc5780Server(boolean dropAll, int errorCode, boolean omitMappedAddress,
				MappingBehavior targetMapping, FilteringBehavior targetFiltering) throws Exception {
			this.dropAll = dropAll;
			this.errorCode = errorCode;
			this.omitMappedAddress = omitMappedAddress;
			this.targetMapping = targetMapping;
			this.targetFiltering = targetFiltering;

			InetAddress loopback = InetAddress.getByName("127.0.0.1");
			this.primarySocket = new DatagramSocket(0, loopback);
			this.alternateSocket = new DatagramSocket(0, loopback);
			this.primarySocket.setSoTimeout(50);
			this.alternateSocket.setSoTimeout(50);

			this.primaryThread = new Thread(() -> serve(primarySocket, true), "SimRfc5780-Primary");
			this.alternateThread = new Thread(() -> serve(alternateSocket, false), "SimRfc5780-Alt");
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
					if (dropAll) {
						continue;
					}

					MessageHeader req = MessageHeader.parseHeader(pkt.getData());
					req.parseAttributes(pkt.getData());
					if (req.getType() != MessageHeaderType.BindingRequest) {
						continue;
					}

					if (errorCode > 0) {
						MessageHeader errResp = new MessageHeader(MessageHeaderType.BindingErrorResponse);
						errResp.setTransactionID(req.getTransactionID());
						ErrorCode ec = new ErrorCode();
						ec.setResponseCode(errorCode);
						errResp.addMessageAttribute(ec);
						sock.send(new DatagramPacket(errResp.getBytes(), errResp.getBytes().length,
								pkt.getAddress(), pkt.getPort()));
						continue;
					}

					if (omitMappedAddress) {
						MessageHeader resp = new MessageHeader(MessageHeaderType.BindingResponse);
						resp.setTransactionID(req.getTransactionID());
						sock.send(new DatagramPacket(resp.getBytes(), resp.getBytes().length,
								pkt.getAddress(), pkt.getPort()));
						continue;
					}

					ChangeRequest cr = (ChangeRequest) req.getMessageAttribute(MessageAttributeType.ChangeRequest);
					boolean changeIP = (cr != null && cr.isChangeIP());
					boolean changePort = (cr != null && cr.isChangePort());

					// Section 4.4 Filtering Test II: changeIP && changePort
					if (changeIP && changePort) {
						if (targetFiltering == FilteringBehavior.ENDPOINT_INDEPENDENT) {
							MessageHeader resp = buildResponse(req, pkt, 60001);
							alternateSocket.send(new DatagramPacket(resp.getBytes(), resp.getBytes().length,
									pkt.getAddress(), pkt.getPort()));
						}
						continue;
					}

					// Section 4.4 Filtering Test III: !changeIP && changePort
					if (!changeIP && changePort) {
						if (targetFiltering == FilteringBehavior.ADDRESS_DEPENDENT) {
							MessageHeader resp = buildResponse(req, pkt, 60001);
							alternateSocket.send(new DatagramPacket(resp.getBytes(), resp.getBytes().length,
									pkt.getAddress(), pkt.getPort()));
						}
						continue;
					}

					// Section 4.3 Mapping Behavior Tests I, II, III (no ChangeRequest flags)
					int mappedPort;
					if (targetMapping == MappingBehavior.DIRECT) {
						mappedPort = pkt.getPort();
					} else if (isPrimary) {
						byte[] txId = req.getTransactionID();
						if (firstPrimaryTxId == null || Arrays.equals(firstPrimaryTxId, txId)) {
							firstPrimaryTxId = txId;
							// Mapping Test I
							mappedPort = 60001;
						} else {
							// Mapping Test II (sent to alternateIP:primaryPort with a new Transaction ID)
							mappedPort = (targetMapping == MappingBehavior.ENDPOINT_INDEPENDENT) ? 60001 : 60002;
						}
					} else {
						// Mapping Test III (sent to alternateIP:alternatePort)
						mappedPort = (targetMapping == MappingBehavior.ADDRESS_DEPENDENT) ? 60002 : 60003;
					}

					MessageHeader resp = buildResponse(req, pkt, mappedPort);
					sock.send(new DatagramPacket(resp.getBytes(), resp.getBytes().length,
							pkt.getAddress(), pkt.getPort()));
				} catch (SocketTimeoutException ste) {
					// continue
				} catch (Exception e) {
					// ignore on shutdown
				}
			}
		}

		private MessageHeader buildResponse(MessageHeader req, DatagramPacket pkt, int mappedPort) throws Exception {
			MessageHeader resp = new MessageHeader(MessageHeaderType.BindingResponse);
			resp.setTransactionID(req.getTransactionID());

			XorMappedAddress xma = new XorMappedAddress(req.getTransactionID());
			if (targetMapping == MappingBehavior.DIRECT) {
				xma.setAddress(new Address(pkt.getAddress().getAddress()));
			} else {
				xma.setAddress(new Address("203.0.113.55"));
			}
			xma.setPort(mappedPort);
			resp.addMessageAttribute(xma);

			OtherAddress oa = new OtherAddress();
			oa.setAddress(new Address("127.0.0.1"));
			oa.setPort(alternateSocket.getLocalPort());
			resp.addMessageAttribute(oa);
			return resp;
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

	private DiscoveryInfo runRfc5780(boolean dropAll, int errorCode, boolean omitMapped,
			MappingBehavior mapping, FilteringBehavior filtering) throws Exception {
		try (SimulatedRfc5780Server server = new SimulatedRfc5780Server(dropAll, errorCode, omitMapped, mapping, filtering)) {
			NatBehaviorDiscoveryTest test = new NatBehaviorDiscoveryTest(
					InetAddress.getByName("127.0.0.1"), "127.0.0.1", server.getPrimaryPort());
			test.setTimeoutInitValue(40);
			test.setMaxWaitTimeMs(80);
			return test.test();
		}
	}

	@Test
	public void testOtherAddressAndResponseOriginRoundTrip() throws Exception {
		MessageHeader mh = new MessageHeader(MessageHeaderType.BindingResponse);
		mh.generateTransactionID();

		OtherAddress oa = new OtherAddress();
		oa.setAddress(new Address("198.51.100.2"));
		oa.setPort(3479);
		mh.addMessageAttribute(oa);

		ResponseOrigin ro = new ResponseOrigin();
		ro.setAddress(new Address("198.51.100.1"));
		ro.setPort(3478);
		mh.addMessageAttribute(ro);

		byte[] bytes = mh.getBytes();
		MessageHeader parsed = MessageHeader.parseHeader(bytes);
		parsed.parseAttributes(bytes);

		OtherAddress parsedOa = (OtherAddress) parsed.getMessageAttribute(MessageAttributeType.OtherAddress);
		assertNotNull(parsedOa);
		assertEquals(new Address("198.51.100.2"), parsedOa.getAddress());
		assertEquals(3479, parsedOa.getPort());

		ResponseOrigin parsedRo = (ResponseOrigin) parsed.getMessageAttribute(MessageAttributeType.ResponseOrigin);
		assertNotNull(parsedRo);
		assertEquals(new Address("198.51.100.1"), parsedRo.getAddress());
		assertEquals(3478, parsedRo.getPort());
	}

	@Test
	public void testResponsePortAndPaddingRoundTrip() throws Exception {
		MessageHeader mh = new MessageHeader(MessageHeaderType.BindingRequest);
		mh.generateTransactionID();

		ResponsePort rp = new ResponsePort(45678);
		mh.addMessageAttribute(rp);

		Padding pad = new Padding(10); // padded to 12 bytes
		mh.addMessageAttribute(pad);

		byte[] bytes = mh.getBytes();
		MessageHeader parsed = MessageHeader.parseHeader(bytes);
		parsed.parseAttributes(bytes);

		ResponsePort parsedRp = (ResponsePort) parsed.getMessageAttribute(MessageAttributeType.ResponsePort);
		assertNotNull(parsedRp);
		assertEquals(45678, parsedRp.getPort());

		Padding parsedPad = (Padding) parsed.getMessageAttribute(MessageAttributeType.Padding);
		assertNotNull(parsedPad);
		assertEquals(12, parsedPad.getPaddingLength());
	}

	@Test
	public void testDiscoveryInfoRfc5780Behaviors() throws Exception {
		DiscoveryInfo di = new DiscoveryInfo(InetAddress.getByName("127.0.0.1"));
		assertEquals(MappingBehavior.UNKNOWN, di.getMappingBehavior());
		assertEquals(FilteringBehavior.UNKNOWN, di.getFilteringBehavior());

		di.setMappingBehavior(MappingBehavior.ENDPOINT_INDEPENDENT);
		di.setFilteringBehavior(FilteringBehavior.ADDRESS_AND_PORT_DEPENDENT);
		di.setPortRestrictedCone();
		di.setPublicIP(InetAddress.getByName("203.0.113.10"));
		di.setPublicPort(50000);

		assertEquals(MappingBehavior.ENDPOINT_INDEPENDENT, di.getMappingBehavior());
		assertEquals(FilteringBehavior.ADDRESS_AND_PORT_DEPENDENT, di.getFilteringBehavior());
		String summary = di.toString();
		assertTrue(summary.contains("ENDPOINT_INDEPENDENT"));
		assertTrue(summary.contains("ADDRESS_AND_PORT_DEPENDENT"));
	}

	@Test
	public void testNatBehaviorDiscoveryBlockedAndErrorCases() throws Exception {
		DiscoveryInfo blocked = runRfc5780(true, 0, false, MappingBehavior.UNKNOWN, FilteringBehavior.UNKNOWN);
		assertTrue(blocked.isBlockedUDP());

		DiscoveryInfo err = runRfc5780(false, 400, false, MappingBehavior.UNKNOWN, FilteringBehavior.UNKNOWN);
		assertTrue(err.isError());
		assertEquals(MappingBehavior.UNKNOWN, err.getMappingBehavior());
		assertEquals(FilteringBehavior.UNKNOWN, err.getFilteringBehavior());

		DiscoveryInfo incomplete = runRfc5780(false, 0, true, MappingBehavior.UNKNOWN, FilteringBehavior.UNKNOWN);
		assertTrue(incomplete.isError());
	}

	@Test
	public void testNatBehaviorDiscoveryDirectMappingCases() throws Exception {
		DiscoveryInfo open = runRfc5780(false, 0, false,
				MappingBehavior.DIRECT, FilteringBehavior.ENDPOINT_INDEPENDENT);
		assertEquals(MappingBehavior.DIRECT, open.getMappingBehavior());
		assertEquals(FilteringBehavior.ENDPOINT_INDEPENDENT, open.getFilteringBehavior());
		assertTrue(open.isOpenAccess());

		DiscoveryInfo firewall = runRfc5780(false, 0, false,
				MappingBehavior.DIRECT, FilteringBehavior.ADDRESS_DEPENDENT);
		assertEquals(MappingBehavior.DIRECT, firewall.getMappingBehavior());
		assertEquals(FilteringBehavior.ADDRESS_DEPENDENT, firewall.getFilteringBehavior());
		assertTrue(firewall.isSymmetricUDPFirewall());
	}

	@Test
	public void testNatBehaviorDiscoveryEndpointIndependentMappingCases() throws Exception {
		DiscoveryInfo fullCone = runRfc5780(false, 0, false,
				MappingBehavior.ENDPOINT_INDEPENDENT, FilteringBehavior.ENDPOINT_INDEPENDENT);
		assertEquals(MappingBehavior.ENDPOINT_INDEPENDENT, fullCone.getMappingBehavior());
		assertEquals(FilteringBehavior.ENDPOINT_INDEPENDENT, fullCone.getFilteringBehavior());
		assertTrue(fullCone.isFullCone());

		DiscoveryInfo restricted = runRfc5780(false, 0, false,
				MappingBehavior.ENDPOINT_INDEPENDENT, FilteringBehavior.ADDRESS_DEPENDENT);
		assertEquals(MappingBehavior.ENDPOINT_INDEPENDENT, restricted.getMappingBehavior());
		assertEquals(FilteringBehavior.ADDRESS_DEPENDENT, restricted.getFilteringBehavior());
		assertTrue(restricted.isRestrictedCone());

		DiscoveryInfo portRestricted = runRfc5780(false, 0, false,
				MappingBehavior.ENDPOINT_INDEPENDENT, FilteringBehavior.ADDRESS_AND_PORT_DEPENDENT);
		assertEquals(MappingBehavior.ENDPOINT_INDEPENDENT, portRestricted.getMappingBehavior());
		assertEquals(FilteringBehavior.ADDRESS_AND_PORT_DEPENDENT, portRestricted.getFilteringBehavior());
		assertTrue(portRestricted.isPortRestrictedCone());
	}

	@Test
	public void testNatBehaviorDiscoveryAddressAndPortDependentMappingCases() throws Exception {
		DiscoveryInfo addrDep = runRfc5780(false, 0, false,
				MappingBehavior.ADDRESS_DEPENDENT, FilteringBehavior.ADDRESS_DEPENDENT);
		assertEquals(MappingBehavior.ADDRESS_DEPENDENT, addrDep.getMappingBehavior());
		assertEquals(FilteringBehavior.ADDRESS_DEPENDENT, addrDep.getFilteringBehavior());
		assertTrue(addrDep.isSymmetric());

		DiscoveryInfo addrPortDep = runRfc5780(false, 0, false,
				MappingBehavior.ADDRESS_AND_PORT_DEPENDENT, FilteringBehavior.ADDRESS_AND_PORT_DEPENDENT);
		assertEquals(MappingBehavior.ADDRESS_AND_PORT_DEPENDENT, addrPortDep.getMappingBehavior());
		assertEquals(FilteringBehavior.ADDRESS_AND_PORT_DEPENDENT, addrPortDep.getFilteringBehavior());
		assertTrue(addrPortDep.isSymmetric());
	}

	@Test
	public void testMtuProbingConstrainedJumboAndLegacyFallback() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");

		// 1. Constrained path (e.g. WireGuard 1420-byte MTU)
		try (SimulatedMtuServer mtu1420 = new SimulatedMtuServer(1420, false)) {
			NatBehaviorDiscoveryTest test = new NatBehaviorDiscoveryTest(loopback, "127.0.0.1", mtu1420.getPort());
			test.setTimeoutInitValue(25);
			test.setMaxWaitTimeMs(40);
			int discovered = test.discoverMtu(576, 9000);
			assertEquals(1420, discovered);
		}

		// 2. Jumbo frame path (9000-byte MTU)
		try (SimulatedMtuServer mtu9000 = new SimulatedMtuServer(9000, false)) {
			NatBehaviorDiscoveryTest test = new NatBehaviorDiscoveryTest(loopback, "127.0.0.1", mtu9000.getPort());
			test.setTimeoutInitValue(50);
			test.setMaxWaitTimeMs(100);
			int discovered = test.discoverMtu(576, 9000);
			assertEquals(9000, discovered);
		}

		// 3. Legacy RFC 3489 server rejecting PADDING with 420 Unknown Attribute -> -1
		try (SimulatedMtuServer legacyServer = new SimulatedMtuServer(1500, true)) {
			NatBehaviorDiscoveryTest test = new NatBehaviorDiscoveryTest(loopback, "127.0.0.1", legacyServer.getPort());
			test.setTimeoutInitValue(40);
			test.setMaxWaitTimeMs(80);
			assertEquals(-1, test.discoverMtu());
		}
	}

	static class SimulatedMtuServer implements AutoCloseable {
		private final DatagramSocket socket;
		private final int maxIpUdpBytes;
		private final boolean rejectPadding;
		private final AtomicBoolean running = new AtomicBoolean(true);
		private final Thread thread;

		SimulatedMtuServer(int maxIpUdpBytes, boolean rejectPadding) throws Exception {
			this.maxIpUdpBytes = maxIpUdpBytes;
			this.rejectPadding = rejectPadding;
			this.socket = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"));
			this.socket.setReceiveBufferSize(65536);
			this.socket.setSendBufferSize(65536);
			this.socket.setSoTimeout(30);
			this.thread = new Thread(this::serve, "SimMtuServer-" + maxIpUdpBytes);
			this.thread.setDaemon(true);
			this.thread.start();
		}

		int getPort() {
			return socket.getLocalPort();
		}

		private void serve() {
			byte[] buf = new byte[10240];
			while (running.get() && !socket.isClosed()) {
				try {
					DatagramPacket pkt = new DatagramPacket(buf, buf.length);
					socket.receive(pkt);
					if (28 + pkt.getLength() > maxIpUdpBytes) {
						continue; // simulate path MTU drop
					}
					byte[] raw = new byte[pkt.getLength()];
					System.arraycopy(buf, 0, raw, 0, raw.length);
					MessageHeader req = MessageHeader.parseHeader(raw);
					req.parseAttributes(raw);
					if (rejectPadding && req.getMessageAttribute(MessageAttributeType.Padding) != null) {
						MessageHeader err = new MessageHeader(MessageHeaderType.BindingErrorResponse);
						err.setTransactionID(req.getTransactionID());
						ErrorCode ec = new ErrorCode();
						ec.setResponseCode(420);
						err.addMessageAttribute(ec);
						byte[] out = err.getBytes();
						socket.send(new DatagramPacket(out, out.length, pkt.getAddress(), pkt.getPort()));
					} else {
						MessageHeader resp = new MessageHeader(MessageHeaderType.BindingResponse);
						resp.setTransactionID(req.getTransactionID());
						MappedAddress ma = new MappedAddress();
						ma.setAddress(new Address(pkt.getAddress().getAddress()));
						ma.setPort(pkt.getPort());
						resp.addMessageAttribute(ma);
						byte[] out = resp.getBytesWithFingerprint();
						socket.send(new DatagramPacket(out, out.length, pkt.getAddress(), pkt.getPort()));
					}
				} catch (SocketTimeoutException ignored) {
				} catch (Exception e) {
					if (running.get() && !socket.isClosed()) {
						e.printStackTrace();
					}
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
