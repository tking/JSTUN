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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.util.Address;

public class Rfc5769TestVectorsTest {

	private static final byte[] RFC5769_HEADER_ID = new byte[] {
		(byte) 0x21, (byte) 0x12, (byte) 0xa4, (byte) 0x42,
		(byte) 0xb7, (byte) 0xe7, (byte) 0xa7, (byte) 0x01,
		(byte) 0xbc, (byte) 0x34, (byte) 0xd6, (byte) 0x86,
		(byte) 0xfa, (byte) 0x87, (byte) 0xdf, (byte) 0xae
	};

	@Test
	public void testRfc5769Section2_2_IPv4XorMappedAddress() throws Exception {
		// RFC 5769 Section 2.2: 192.0.2.1:32853
		// Expected XOR-MAPPED-ADDRESS value bytes: 00 01 a1 47 e1 12 a6 43
		byte[] wireValue = new byte[] {
			(byte) 0x00, (byte) 0x01, (byte) 0xa1, (byte) 0x47,
			(byte) 0xe1, (byte) 0x12, (byte) 0xa6, (byte) 0x43
		};

		XorMappedAddress parsed = (XorMappedAddress) XorMappedAddress.parse(wireValue, RFC5769_HEADER_ID);
		assertEquals(32853, parsed.getPort());
		assertEquals(new Address("192.0.2.1"), parsed.getAddress());

		byte[] serialized = parsed.getBytes(RFC5769_HEADER_ID);
		byte[] expectedFullAttr = new byte[] {
			(byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x08,
			(byte) 0x00, (byte) 0x01, (byte) 0xa1, (byte) 0x47,
			(byte) 0xe1, (byte) 0x12, (byte) 0xa6, (byte) 0x43
		};
		assertArrayEquals(expectedFullAttr, serialized);
	}

	@Test
	public void testRfc5769Section2_3_IPv6XorMappedAddress() throws Exception {
		// RFC 5769 Section 2.3: 2001:db8:1234:5678:11:2233:4455:6677, port 32853
		byte[] wireValue = new byte[] {
			(byte) 0x00, (byte) 0x02, (byte) 0xa1, (byte) 0x47,
			(byte) 0x01, (byte) 0x13, (byte) 0xa9, (byte) 0xfa,
			(byte) 0xa5, (byte) 0xd3, (byte) 0xf1, (byte) 0x79,
			(byte) 0xbc, (byte) 0x25, (byte) 0xf4, (byte) 0xb5,
			(byte) 0xbe, (byte) 0xd2, (byte) 0xb9, (byte) 0xd9
		};

		XorMappedAddress parsed = (XorMappedAddress) XorMappedAddress.parse(wireValue, RFC5769_HEADER_ID);
		assertEquals(32853, parsed.getPort());
		assertEquals(new Address("2001:db8:1234:5678:11:2233:4455:6677"), parsed.getAddress());

		byte[] serialized = parsed.getBytes(RFC5769_HEADER_ID);
		byte[] expectedFullAttr = new byte[] {
			(byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x14,
			(byte) 0x00, (byte) 0x02, (byte) 0xa1, (byte) 0x47,
			(byte) 0x01, (byte) 0x13, (byte) 0xa9, (byte) 0xfa,
			(byte) 0xa5, (byte) 0xd3, (byte) 0xf1, (byte) 0x79,
			(byte) 0xbc, (byte) 0x25, (byte) 0xf4, (byte) 0xb5,
			(byte) 0xbe, (byte) 0xd2, (byte) 0xb9, (byte) 0xd9
		};
		assertArrayEquals(expectedFullAttr, serialized);
	}

	@Test
	public void testRfc5769Section2_2_FullIPv4ResponsePacket() throws Exception {
		// Complete 80-byte STUN Binding Response from RFC 5769 Section 2.2
		byte[] packet = new byte[] {
			(byte) 0x01, (byte) 0x01, (byte) 0x00, (byte) 0x3c,
			(byte) 0x21, (byte) 0x12, (byte) 0xa4, (byte) 0x42,
			(byte) 0xb7, (byte) 0xe7, (byte) 0xa7, (byte) 0x01,
			(byte) 0xbc, (byte) 0x34, (byte) 0xd6, (byte) 0x86,
			(byte) 0xfa, (byte) 0x87, (byte) 0xdf, (byte) 0xae,
			// SOFTWARE: "test vector" (length 11, padded to 12 with 0x20)
			(byte) 0x80, (byte) 0x22, (byte) 0x00, (byte) 0x0b,
			(byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74,
			(byte) 0x20, (byte) 0x76, (byte) 0x65, (byte) 0x63,
			(byte) 0x74, (byte) 0x6f, (byte) 0x72, (byte) 0x20,
			// XOR-MAPPED-ADDRESS: 192.0.2.1:32853
			(byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x08,
			(byte) 0x00, (byte) 0x01, (byte) 0xa1, (byte) 0x47,
			(byte) 0xe1, (byte) 0x12, (byte) 0xa6, (byte) 0x43,
			// MESSAGE-INTEGRITY (HMAC-SHA1 with key "VOkJxbRl1RmTxUk/WvJxBt")
			(byte) 0x00, (byte) 0x08, (byte) 0x00, (byte) 0x14,
			(byte) 0x2b, (byte) 0x91, (byte) 0xf5, (byte) 0x99,
			(byte) 0xfd, (byte) 0x9e, (byte) 0x90, (byte) 0xc3,
			(byte) 0x8c, (byte) 0x74, (byte) 0x89, (byte) 0xf9,
			(byte) 0x2a, (byte) 0xf9, (byte) 0xba, (byte) 0x53,
			(byte) 0xf0, (byte) 0x6b, (byte) 0xe7, (byte) 0xd7,
			// FINGERPRINT
			(byte) 0x80, (byte) 0x28, (byte) 0x00, (byte) 0x04,
			(byte) 0xc0, (byte) 0x7d, (byte) 0x4c, (byte) 0x96
		};

		MessageHeader mh = MessageHeader.parseHeader(packet);
		assertEquals(MessageHeaderType.BindingResponse, mh.getType());
		mh.parseAttributes(packet);
		assertTrue(mh.hasMagicCookie());

		Software sw = (Software) mh.getMessageAttribute(MessageAttributeType.Software);
		assertNotNull(sw);
		assertEquals("test vector", sw.getSoftware());

		XorMappedAddress xma = (XorMappedAddress) mh.getMessageAttribute(MessageAttributeType.XorMappedAddress);
		assertNotNull(xma);
		assertEquals(32853, xma.getPort());
		assertEquals(new Address("192.0.2.1"), xma.getAddress());

		MessageIntegrity mi = (MessageIntegrity) mh.getMessageAttribute(MessageAttributeType.MessageIntegrity);
		assertNotNull(mi);
		byte[] prefixBeforeIntegrity = new byte[48];
		System.arraycopy(packet, 0, prefixBeforeIntegrity, 0, 48);
		assertTrue(mi.verifyShortTerm(prefixBeforeIntegrity, "VOkJxbRl1RmTxUk/WvJxBt"));

		Fingerprint fp = (Fingerprint) mh.getMessageAttribute(MessageAttributeType.Fingerprint);
		assertNotNull(fp);
		assertEquals(0xc07d4c96L, fp.getCrc());
		assertTrue(Fingerprint.verify(packet));
	}

	@Test
	public void testRfc5769Section2_3_FullIPv6ResponsePacket() throws Exception {
		// Complete 92-byte STUN Binding Response from RFC 5769 Section 2.3
		byte[] packet = new byte[] {
			(byte) 0x01, (byte) 0x01, (byte) 0x00, (byte) 0x48,
			(byte) 0x21, (byte) 0x12, (byte) 0xa4, (byte) 0x42,
			(byte) 0xb7, (byte) 0xe7, (byte) 0xa7, (byte) 0x01,
			(byte) 0xbc, (byte) 0x34, (byte) 0xd6, (byte) 0x86,
			(byte) 0xfa, (byte) 0x87, (byte) 0xdf, (byte) 0xae,
			// SOFTWARE: "test vector"
			(byte) 0x80, (byte) 0x22, (byte) 0x00, (byte) 0x0b,
			(byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74,
			(byte) 0x20, (byte) 0x76, (byte) 0x65, (byte) 0x63,
			(byte) 0x74, (byte) 0x6f, (byte) 0x72, (byte) 0x20,
			// XOR-MAPPED-ADDRESS: 2001:db8:1234:5678:11:2233:4455:6677, port 32853
			(byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x14,
			(byte) 0x00, (byte) 0x02, (byte) 0xa1, (byte) 0x47,
			(byte) 0x01, (byte) 0x13, (byte) 0xa9, (byte) 0xfa,
			(byte) 0xa5, (byte) 0xd3, (byte) 0xf1, (byte) 0x79,
			(byte) 0xbc, (byte) 0x25, (byte) 0xf4, (byte) 0xb5,
			(byte) 0xbe, (byte) 0xd2, (byte) 0xb9, (byte) 0xd9,
			// MESSAGE-INTEGRITY
			(byte) 0x00, (byte) 0x08, (byte) 0x00, (byte) 0x14,
			(byte) 0xa3, (byte) 0x82, (byte) 0x95, (byte) 0x4e,
			(byte) 0x4b, (byte) 0xe6, (byte) 0x7b, (byte) 0xf1,
			(byte) 0x17, (byte) 0x84, (byte) 0xc9, (byte) 0x7c,
			(byte) 0x82, (byte) 0x92, (byte) 0xc2, (byte) 0x75,
			(byte) 0xbf, (byte) 0xe3, (byte) 0xed, (byte) 0x41,
			// FINGERPRINT
			(byte) 0x80, (byte) 0x28, (byte) 0x00, (byte) 0x04,
			(byte) 0xc8, (byte) 0xfb, (byte) 0x0b, (byte) 0x4c
		};

		MessageHeader mh = MessageHeader.parseHeader(packet);
		assertEquals(MessageHeaderType.BindingResponse, mh.getType());
		mh.parseAttributes(packet);

		XorMappedAddress xma = (XorMappedAddress) mh.getMessageAttribute(MessageAttributeType.XorMappedAddress);
		assertNotNull(xma);
		assertEquals(32853, xma.getPort());
		assertEquals(new Address("2001:db8:1234:5678:11:2233:4455:6677"), xma.getAddress());

		MessageIntegrity mi = (MessageIntegrity) mh.getMessageAttribute(MessageAttributeType.MessageIntegrity);
		assertNotNull(mi);
		byte[] prefixBeforeIntegrity = new byte[60];
		System.arraycopy(packet, 0, prefixBeforeIntegrity, 0, 60);
		assertTrue(mi.verifyShortTerm(prefixBeforeIntegrity, "VOkJxbRl1RmTxUk/WvJxBt"));

		Fingerprint fp = (Fingerprint) mh.getMessageAttribute(MessageAttributeType.Fingerprint);
		assertNotNull(fp);
		assertEquals(0xc8fb0b4cL, fp.getCrc());
		assertTrue(Fingerprint.verify(packet));
	}

	@Test
	public void testComprehensionOptionalAttributesSkippedWithPadding() throws Exception {
		// Packet with an unknown comprehension-optional attribute (0x8099, 5 bytes value + 3 bytes padding)
		// followed by a standard XOR-MAPPED-ADDRESS attribute
		MessageHeader mh = new MessageHeader(MessageHeaderType.BindingResponse);
		mh.generateTransactionID();
		byte[] txId = mh.getTransactionID();

		XorMappedAddress xma = new XorMappedAddress(txId);
		xma.setAddress(new Address("203.0.113.5"));
		xma.setPort(54321);
		byte[] xmaBytes = xma.getBytes(txId);

		// Unknown optional attribute: type 0x8099, length 5, padded to 8 bytes (total 12 bytes)
		byte[] unknownOpt = new byte[] {
			(byte) 0x80, (byte) 0x99, (byte) 0x00, (byte) 0x05,
			1, 2, 3, 4, 5, 0, 0, 0
		};

		int payloadLen = unknownOpt.length + xmaBytes.length;
		byte[] packet = new byte[20 + payloadLen];
		packet[0] = 0x01;
		packet[1] = 0x01;
		packet[2] = (byte) ((payloadLen >>> 8) & 0xFF);
		packet[3] = (byte) (payloadLen & 0xFF);
		System.arraycopy(txId, 0, packet, 4, 16);
		System.arraycopy(unknownOpt, 0, packet, 20, unknownOpt.length);
		System.arraycopy(xmaBytes, 0, packet, 20 + unknownOpt.length, xmaBytes.length);

		MessageHeader parsed = MessageHeader.parseHeader(packet);
		parsed.parseAttributes(packet);

		XorMappedAddress parsedXma = (XorMappedAddress) parsed.getMessageAttribute(MessageAttributeType.XorMappedAddress);
		assertNotNull(parsedXma);
		assertEquals(54321, parsedXma.getPort());
		assertEquals(new Address("203.0.113.5"), parsedXma.getAddress());
	}

	@Test
	public void testIssue21CoturnErrorResponsePacket() throws Exception {
		// Exact Coturn-4.5.2 BindingErrorResponse hex dump reported in GitHub Issue #21
		String hex = "01110070f4a21402935aef2941f7426af83c01ab"
				+ "0009004c00000414556e6b6e6f776e206174747269627574653a205455524e20"
				+ "7365727665722077617320636f6e6669677572656420776974686f7574205246"
				+ "43203537383020737570706f72740000"
				+ "8022001c436f7475726e2d342e352e32202764616e2045696465722700000000";
		byte[] packet = new byte[hex.length() / 2];
		for (int i = 0; i < packet.length; i++) {
			packet[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
		}

		MessageHeader parsed = MessageHeader.parseHeader(packet);
		assertEquals(MessageHeaderType.BindingErrorResponse, parsed.getType());
		parsed.parseAttributes(packet);

		ErrorCode ec = (ErrorCode) parsed.getMessageAttribute(MessageAttributeType.ErrorCode);
		assertNotNull(ec);
		assertEquals(420, ec.getResponseCode());
		assertEquals("Unknown attribute: TURN server was configured without RFC 5780 support", ec.getReason());
		assertNotNull(ec.getBytes());

		Software sw = (Software) parsed.getMessageAttribute(MessageAttributeType.Software);
		assertNotNull(sw);
		assertEquals("Coturn-4.5.2 'dan Eider'", sw.getSoftware());
	}
}
