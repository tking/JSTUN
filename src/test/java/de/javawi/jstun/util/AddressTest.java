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

package de.javawi.jstun.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class AddressTest {
	Address ipv4Address;
	Address ipv6Address;

	@BeforeEach
	protected void setUp() throws Exception {
		ipv4Address = new Address("192.168.100.1");
		ipv6Address = new Address("2001:0db8:85a3:08d3:1319:8a2e:0370:7344");
	}

	/*
	 * Test method for 'de.javawi.jstun.util.Address.Address(int, int, int, int)'
	 */
	@Test
	public void testAddressV4IntIntIntInt() {
		try {
			Address comp = new Address(192, 168, 100, 1);
			assertTrue(ipv4Address.equals(comp));
		} catch (UtilityException ue) {
			ue.printStackTrace();
		}
	}

	/*
	 * Test method for 'de.javawi.jstun.util.Address.Address(int[])'
	 */
	@Test
	public void testAddressV4IntArray() {
		try {
			int[] data = { 192, 168, 100, 1 };
			Address comp = new Address(data);
			assertTrue(ipv4Address.equals(comp));
		} catch (UtilityException ue) {
			ue.printStackTrace();
		}
	}

	/*
	 * Test method for 'de.javawi.jstun.util.Address.Address(int[])'
	 */
	@Test
	public void testAddressV6Int16Array() {
		try {
			int[] data = { 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73,
					0x44 };
			Address comp = new Address(data);
			assertTrue(ipv6Address.equals(comp));
		} catch (UtilityException ue) {
			ue.printStackTrace();
		}
	}

	/*
	 * Test method for 'de.javawi.jstun.util.Address.Address(String)'
	 */
	@Test
	public void testAddressV4String() {
		try {
			Address comp = new Address("192.168.100.1");
			assertTrue(ipv4Address.equals(comp));
		} catch (UtilityException ue) {
			ue.printStackTrace();
		}
	}

	/*
	 * Test method for 'de.javawi.jstun.util.Address.Address(String)'
	 */
	@Test
	public void testAddressV6String() {
		try {
			Address comp = new Address("2001:0db8:85a3:08d3:1319:8a2e:0370:7344");
			assertTrue(ipv6Address.equals(comp));
		} catch (UtilityException ue) {
			ue.printStackTrace();
		}
	}

	/*
	 * Test method for 'de.javawi.jstun.util.Address.Address(byte[])'
	 */
	@Test
	public void testAddressV4ByteArray() {
		try {
			byte[] data = { (byte) 192, (byte) 168, (byte) 100, (byte) 1 };
			Address comp = new Address(data);
			assertTrue(ipv4Address.equals(comp));
		} catch (UtilityException ue) {
			ue.printStackTrace();
		}
	}

	/*
	 * Test method for 'de.javawi.jstun.util.Address.Address(byte[])'
	 */
	@Test
	public void testAddressV6ByteArray() {
		try {
			byte[] data = { (byte) 0x20, (byte) 0x01, (byte) 0x0d, (byte) 0xb8, (byte) 0x85, (byte) 0xa3, (byte) 0x08,
					(byte) 0xd3, (byte) 0x13, (byte) 0x19, (byte) 0x8a, (byte) 0x2e, (byte) 0x03, (byte) 0x70,
					(byte) 0x73, (byte) 0x44 };
			Address comp = new Address(data);
			assertTrue(ipv6Address.equals(comp));
		} catch (UtilityException ue) {
			ue.printStackTrace();
		}
	}

	/*
	 * Test method for 'de.javawi.jstun.util.Address.toString()'
	 */
	@Test
	public void testV4ToString() {
		String comp = "192.168.100.1";
		assertTrue(ipv4Address.toString().equals(comp));
	}

	/*
	 * Test method for 'de.javawi.jstun.util.Address.toString()'
	 */
	@Test
	public void testV6ToString() {
		String comp = "2001:db8:85a3:8d3:1319:8a2e:370:7344";

		assertEquals(ipv6Address.toString(), comp);
	}

	/*
	 * Test method for 'de.javawi.jstun.util.Address.getBytes()'
	 */
	@Test
	public void testV4GetBytes() {
		try {
			byte[] data = ipv4Address.getBytes();
			assertTrue(data[0] == (byte) 192);
			assertTrue(data[1] == (byte) 168);
			assertTrue(data[2] == (byte) 100);
			assertTrue(data[3] == (byte) 1);
		} catch (UtilityException ue) {
			ue.printStackTrace();
		}

	}

	/*
	 * Test method for 'de.javawi.jstun.util.Address.getBytes()'
	 */
	@Test
	public void testV6GetBytes() {
		try {
			byte[] data = ipv6Address.getBytes();
			assertTrue(data[0] == (byte) 0x20);
			assertTrue(data[1] == (byte) 0x01);
			assertTrue(data[2] == (byte) 0x0d);
			assertTrue(data[3] == (byte) 0xb8);
			assertTrue(data[4] == (byte) 0x85);
			assertTrue(data[5] == (byte) 0xa3);
			assertTrue(data[6] == (byte) 0x08);
			assertTrue(data[7] == (byte) 0xd3);
			assertTrue(data[8] == (byte) 0x13);
			assertTrue(data[9] == (byte) 0x19);
			assertTrue(data[10] == (byte) 0x8a);
			assertTrue(data[11] == (byte) 0x2e);
			assertTrue(data[12] == (byte) 0x03);
			assertTrue(data[13] == (byte) 0x70);
			assertTrue(data[14] == (byte) 0x73);
			assertTrue(data[15] == (byte) 0x44);
		} catch (UtilityException ue) {
			ue.printStackTrace();
		}

	}

	/*
	 * Test method for 'de.javawi.jstun.util.Address.getInetAddress()'
	 */
	@Test
	public void testV4GetInetAddress() {
		try {
			Address comp = new Address("192.168.100.1");
			assertTrue(ipv4Address.getInetAddress().equals(comp.getInetAddress()));
			comp = new Address("192.168.100.2");
			assertFalse(ipv4Address.getInetAddress().equals(comp.getInetAddress()));
		} catch (UtilityException ue) {
			ue.printStackTrace();
		} catch (java.net.UnknownHostException uhe) {
			uhe.printStackTrace();
		}
	}

	/*
	 * Test method for 'de.javawi.jstun.util.Address.getInetAddress()'
	 */
	@Test
	public void testV6GetInetAddress() {
		try {
			Address comp = new Address("2001:0db8:85a3:08d3:1319:8a2e:0370:7344");
			assertTrue(ipv6Address.getInetAddress().equals(comp.getInetAddress()));
			comp = new Address("2001:0db8:85a3:08d3:1319:8a2e:0370:7345");
			assertFalse(ipv6Address.getInetAddress().equals(comp.getInetAddress()));
		} catch (UtilityException ue) {
			ue.printStackTrace();
		} catch (java.net.UnknownHostException uhe) {
			uhe.printStackTrace();
		}
	}

	/*
	 * Test method for 'de.javawi.jstun.util.Address.equals(Object)'
	 */
	@Test
	public void testV4EqualsObject() {
		try {
			Address comp = new Address("192.168.100.1");
			assertTrue(ipv4Address.equals(comp));
			comp = new Address("192.168.100.2");
			assertFalse(ipv4Address.equals(comp));
		} catch (UtilityException ue) {
			ue.printStackTrace();
		}
	}

	/*
	 * Test method for 'de.javawi.jstun.util.Address.equals(Object)'
	 */
	@Test
	public void testV6EqualsObject() {
		try {
			Address comp = new Address("2001:0db8:85a3:08d3:1319:8a2e:0370:7344");
			assertTrue(ipv6Address.equals(comp));
			comp = new Address("2001:0db8:85a3:08d3:1319:8a2e:0370:7345");
			assertFalse(ipv6Address.equals(comp));
		} catch (UtilityException ue) {
			ue.printStackTrace();
		}
	}
}
