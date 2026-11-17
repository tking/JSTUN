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

import static org.junit.jupiter.api.Assertions.*;

import java.net.InetAddress;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.test.DiscoveryInfo.FilteringBehavior;
import de.javawi.jstun.test.DiscoveryInfo.MappingBehavior;

public class DiscoveryInfoTest {

	@Test
	public void testDefaultStateAndLocalIP() throws Exception {
		InetAddress local = InetAddress.getByName("127.0.0.1");
		DiscoveryInfo di = new DiscoveryInfo(local);

		assertEquals(local, di.getLocalIP());
		assertNull(di.getPublicIP());
		assertEquals(-1, di.getPublicPort());
		assertFalse(di.isError());
		assertFalse(di.isOpenAccess());
		assertFalse(di.isBlockedUDP());
		assertFalse(di.isFullCone());
		assertFalse(di.isRestrictedCone());
		assertFalse(di.isPortRestrictedCone());
		assertFalse(di.isSymmetric());
		assertFalse(di.isSymmetricUDPFirewall());
		assertEquals(MappingBehavior.UNKNOWN, di.getMappingBehavior());
		assertEquals(FilteringBehavior.UNKNOWN, di.getFilteringBehavior());
		assertEquals(-1, di.getDiscoveredMtu());

		String text = di.toString();
		assertTrue(text.contains("127.0.0.1"));
		assertTrue(text.contains("unkown"));
	}

	@Test
	public void testAllNatTypesAndFlags() throws Exception {
		InetAddress local = InetAddress.getByName("192.168.1.100");
		InetAddress pub = InetAddress.getByName("203.0.113.1");

		// Open Access
		DiscoveryInfo di = new DiscoveryInfo(local);
		di.setOpenAccess();
		di.setPublicIP(pub);
		di.setPublicPort(3478);
		assertTrue(di.isOpenAccess());
		assertEquals(pub, di.getPublicIP());
		assertEquals(3478, di.getPublicPort());
		assertTrue(di.toString().contains("Open access to the Internet."));

		// Blocked UDP
		di = new DiscoveryInfo(local);
		di.setBlockedUDP();
		assertTrue(di.isBlockedUDP());
		assertTrue(di.toString().contains("Firewall blocks UDP."));

		// Full Cone
		di = new DiscoveryInfo(local);
		di.setFullCone();
		assertTrue(di.isFullCone());
		assertTrue(di.toString().contains("Full Cone NAT handles connections."));

		// Restricted Cone
		di = new DiscoveryInfo(local);
		di.setRestrictedCone();
		assertTrue(di.isRestrictedCone());
		assertTrue(di.toString().contains("Restricted Cone NAT handles connections."));

		// Port Restricted Cone
		di = new DiscoveryInfo(local);
		di.setPortRestrictedCone();
		assertTrue(di.isPortRestrictedCone());
		assertTrue(di.toString().contains("Port restricted Cone NAT handles connections."));

		// Symmetric
		di = new DiscoveryInfo(local);
		di.setSymmetric();
		assertTrue(di.isSymmetric());
		assertTrue(di.toString().contains("Symmetric Cone NAT handles connections."));

		// Symmetric UDP Firewall
		di = new DiscoveryInfo(local);
		di.setSymmetricUDPFirewall();
		assertTrue(di.isSymmetricUDPFirewall());
		assertTrue(di.toString().contains("Symmetric UDP Firewall handles connections."));
	}

	@Test
	public void testRfc5780Behaviors() throws Exception {
		InetAddress local = InetAddress.getByName("127.0.0.1");
		DiscoveryInfo di = new DiscoveryInfo(local);

		di.setMappingBehavior(MappingBehavior.ENDPOINT_INDEPENDENT);
		assertEquals(MappingBehavior.ENDPOINT_INDEPENDENT, di.getMappingBehavior());

		di.setFilteringBehavior(FilteringBehavior.ADDRESS_DEPENDENT);
		assertEquals(FilteringBehavior.ADDRESS_DEPENDENT, di.getFilteringBehavior());

		String text = di.toString();
		assertTrue(text.contains("RFC 5780 Mapping Behavior: ENDPOINT_INDEPENDENT"));
		assertTrue(text.contains("RFC 5780 Filtering Behavior: ADDRESS_DEPENDENT"));

		di.setMappingBehavior(null);
		assertEquals(MappingBehavior.UNKNOWN, di.getMappingBehavior());

		di.setFilteringBehavior(null);
		assertEquals(FilteringBehavior.UNKNOWN, di.getFilteringBehavior());

		assertEquals(-1, di.getDiscoveredMtu());
		di.setDiscoveredMtu(9000);
		assertEquals(9000, di.getDiscoveredMtu());
		assertTrue(di.toString().contains("RFC 5780 Discovered Path MTU: 9000 bytes"));
	}

	@Test
	public void testErrorStateSuppressesResults() throws Exception {
		InetAddress local = InetAddress.getByName("127.0.0.1");
		DiscoveryInfo di = new DiscoveryInfo(local);
		di.setOpenAccess();
		di.setFullCone();
		di.setBlockedUDP();
		di.setRestrictedCone();
		di.setPortRestrictedCone();
		di.setSymmetric();
		di.setSymmetricUDPFirewall();
		di.setMappingBehavior(MappingBehavior.DIRECT);
		di.setFilteringBehavior(FilteringBehavior.ENDPOINT_INDEPENDENT);
		di.setDiscoveredMtu(1500);

		di.setError(500, "Server Error");
		assertTrue(di.isError());
		assertFalse(di.isOpenAccess());
		assertFalse(di.isFullCone());
		assertFalse(di.isBlockedUDP());
		assertFalse(di.isRestrictedCone());
		assertFalse(di.isPortRestrictedCone());
		assertFalse(di.isSymmetric());
		assertFalse(di.isSymmetricUDPFirewall());
		assertEquals(MappingBehavior.UNKNOWN, di.getMappingBehavior());
		assertEquals(FilteringBehavior.UNKNOWN, di.getFilteringBehavior());
		assertEquals(-1, di.getDiscoveredMtu());

		String text = di.toString();
		assertTrue(text.contains("Server Error - Responsecode: 500"));
	}
}
