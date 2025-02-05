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

import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface;
import de.javawi.jstun.util.UtilityException;
import junit.framework.TestCase;

import java.io.IOException;
import java.net.*;

public class MappedAddressTest extends TestCase {
	MappedAddress maV4;
	MappedAddress maV6;
	byte[] dataV4;
	byte[] dataV6;

	public MappedAddressTest(String mesg) {
		super(mesg);
	}

	public void setUp() throws Exception {
		dataV4 = new byte[8];
		dataV4[0] = 0; // IPv4 family
		dataV4[1] = 1;
		dataV4[2] = -8; // Port
		dataV4[3] = 96;
		dataV4[4] = 84;
		dataV4[5] = 56;
		dataV4[6] = -23;
		dataV4[7] = 76;
		maV4 = (MappedAddress) MappedAddress.parse(dataV4);

		dataV6 = new byte[20];
		dataV6[0] = 0; // IPv6 family
		dataV6[1] = 2;
		dataV6[2] = -8; // Port
		dataV6[3] = 96;
		dataV6[4] = (byte)0x20;
		dataV6[5] = (byte)0x01;
		dataV6[6] = (byte)0x0d;
		dataV6[7] = (byte)0xb8;
		dataV6[8] = (byte)0x85;
		dataV6[9] = (byte)0xa3;
		dataV6[10] = (byte)0x08;
		dataV6[11] = (byte)0xd3;
		dataV6[12] = (byte)0x13;
		dataV6[13] = (byte)0x19;
		dataV6[14] = (byte)0x8a;
		dataV6[15] = (byte)0x2e;
		dataV6[16] = (byte)0x03;
		dataV6[17] = (byte)0x70;
		dataV6[18] = (byte)0x73;
		dataV6[19] = (byte)0x44;
		maV6 = (MappedAddress) MappedAddress.parse(dataV6);
	}

	/*
	 * Test method for 'de.javawi.jstun.attribute.MappedAddress.MappedAddress()'
	 */
	public void testMappedAddress() {
		new MappedAddress();
	}

	/*
	 * Test method for 'de.javawi.jstun.attribute.MappedResponseChangedSourceAddressReflectedFrom.getBytes()'
	 */
	public void testV4GetBytes() {
		try {
			byte[] result = maV4.getBytes();

			assertTrue(result[0] == 0);
			assertTrue(result[1] == 1);
			assertTrue(result[2] == 0);
			assertTrue(result[3] == 8);
			assertTrue(result[4] == dataV4[0]);
			assertTrue(result[5] == dataV4[1]);
			assertTrue(result[6] == dataV4[2]);
			assertTrue(result[7] == dataV4[3]);
			assertTrue(result[8] == dataV4[4]);
			assertTrue(result[9] == dataV4[5]);
			assertTrue(result[10] == dataV4[6]);
			assertTrue(result[11] == dataV4[7]);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/*
	 * Test method for 'de.javawi.jstun.attribute.MappedResponseChangedSourceAddressReflectedFrom.getBytes()'
	 */
	public void testV6GetBytes() {
		try {
			byte[] result = maV6.getBytes();

			assertTrue(result[0] == 0);
			assertTrue(result[1] == 1);
			assertTrue(result[2] == 0);
			assertTrue(result[3] == 8);
			assertTrue(result[4] == dataV6[0]);
			assertTrue(result[5] == dataV6[1]);
			assertTrue(result[6] == dataV6[2]);
			assertTrue(result[7] == dataV6[3]);
			assertTrue(result[8] == dataV6[4]);
			assertTrue(result[9] == dataV6[5]);
			assertTrue(result[10] == dataV6[6]);
			assertTrue(result[11] == dataV6[7]);
			assertTrue(result[12] == dataV6[8]);
			assertTrue(result[13] == dataV6[9]);
			assertTrue(result[14] == dataV6[10]);
			assertTrue(result[15] == dataV6[11]);
			assertTrue(result[16] == dataV6[12]);
			assertTrue(result[17] == dataV6[13]);
			assertTrue(result[18] == dataV6[14]);
			assertTrue(result[19] == dataV6[15]);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/*
	 * Test method for 'de.javawi.jstun.attribute.MappedResponseChangedSourceAddressReflectedFrom.getPort()'
	 */
	public void testGetPort() {
		assertTrue(maV4.getPort() == 63584);
		assertTrue(maV6.getPort() == 63584);
	}

	/*
	 * Test method for 'de.javawi.jstun.attribute.MappedResponseChangedSourceAddressReflectedFrom.getAddress()'
	 */
	public void testV4GetAddress() {
		try {
			assertTrue(maV4.getAddress().equals(new de.javawi.jstun.util.Address("84.56.233.76")));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/*
	 * Test method for 'de.javawi.jstun.attribute.MappedResponseChangedSourceAddressReflectedFrom.getAddress()'
	 */
	public void testV6GetAddress() {
		try {
			assertTrue(maV6.getAddress().equals(new de.javawi.jstun.util.Address("2001:db8:85a3:8d3:1319:8a2e:370:7344")));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/*
	 * Test method for 'de.javawi.jstun.attribute.MappedResponseChangedSourceAddressReflectedFrom.setPort(int)'
	 */
	public void testSetPort() {

	}

	/*
	 * Test method for 'de.javawi.jstun.attribute.MappedResponseChangedSourceAddressReflectedFrom.setAddress(Address)'
	 */
	public void testSetAddress() {

	}

	/*
	 * Test method for 'de.javawi.jstun.attribute.MappedResponseChangedSourceAddressReflectedFrom.toString()'
	 */
	public void testToString() {

	}

}
