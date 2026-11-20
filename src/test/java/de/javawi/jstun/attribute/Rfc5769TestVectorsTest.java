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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.util.Address;
import de.javawi.jstun.util.SaslPrep;
import de.javawi.jstun.util.UtilityException;

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
		assertTrue(MessageHeader.verifyShortTermMessageIntegrity(packet, "VOkJxbRl1RmTxUk/WvJxBt"));

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
		assertTrue(MessageHeader.verifyShortTermMessageIntegrity(packet, "VOkJxbRl1RmTxUk/WvJxBt"));

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

	@Test
	public void testRfc5769Section2_1_SampleRequest() throws Exception {
		// Exact 108-byte STUN Binding Request from RFC 5769 Section 2.1 / Appendix A
		byte[] packet = new byte[] {
			// Header: BindingRequest (0x0001), length 0x0058 (88 bytes), Magic Cookie, Transaction ID
			(byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x58,
			(byte) 0x21, (byte) 0x12, (byte) 0xa4, (byte) 0x42,
			(byte) 0xb7, (byte) 0xe7, (byte) 0xa7, (byte) 0x01,
			(byte) 0xbc, (byte) 0x34, (byte) 0xd6, (byte) 0x86,
			(byte) 0xfa, (byte) 0x87, (byte) 0xdf, (byte) 0xae,
			// SOFTWARE (0x8022): "STUN test client" (16 bytes)
			(byte) 0x80, (byte) 0x22, (byte) 0x00, (byte) 0x10,
			(byte) 0x53, (byte) 0x54, (byte) 0x55, (byte) 0x4e,
			(byte) 0x20, (byte) 0x74, (byte) 0x65, (byte) 0x73,
			(byte) 0x74, (byte) 0x20, (byte) 0x63, (byte) 0x6c,
			(byte) 0x69, (byte) 0x65, (byte) 0x6e, (byte) 0x74,
			// PRIORITY (0x0024): 0x6e0001ff
			(byte) 0x00, (byte) 0x24, (byte) 0x00, (byte) 0x04,
			(byte) 0x6e, (byte) 0x00, (byte) 0x01, (byte) 0xff,
			// ICE-CONTROLLED (0x8029, comprehension-optional): 8-byte tie breaker
			(byte) 0x80, (byte) 0x29, (byte) 0x00, (byte) 0x08,
			(byte) 0x93, (byte) 0x2f, (byte) 0xf9, (byte) 0xb1,
			(byte) 0x51, (byte) 0x26, (byte) 0x3b, (byte) 0x36,
			// USERNAME (0x0006): "evtj:h6vY" (9 bytes) + 3 ASCII space padding bytes
			(byte) 0x00, (byte) 0x06, (byte) 0x00, (byte) 0x09,
			(byte) 0x65, (byte) 0x76, (byte) 0x74, (byte) 0x6a,
			(byte) 0x3a, (byte) 0x68, (byte) 0x36, (byte) 0x76,
			(byte) 0x59, (byte) 0x20, (byte) 0x20, (byte) 0x20,
			// MESSAGE-INTEGRITY (0x0008): HMAC-SHA1 with key "VOkJxbRl1RmTxUk/WvJxBt"
			(byte) 0x00, (byte) 0x08, (byte) 0x00, (byte) 0x14,
			(byte) 0x9a, (byte) 0xea, (byte) 0xa7, (byte) 0x0c,
			(byte) 0xbf, (byte) 0xd8, (byte) 0xcb, (byte) 0x56,
			(byte) 0x78, (byte) 0x1e, (byte) 0xf2, (byte) 0xb5,
			(byte) 0xb2, (byte) 0xd3, (byte) 0xf2, (byte) 0x49,
			(byte) 0xc1, (byte) 0xb5, (byte) 0x71, (byte) 0xa2,
			// FINGERPRINT (0x8028): CRC32 ^ 0x5354554e
			(byte) 0x80, (byte) 0x28, (byte) 0x00, (byte) 0x04,
			(byte) 0xe5, (byte) 0x7a, (byte) 0x3b, (byte) 0xcf
		};
		assertEquals(108, packet.length);

		MessageHeader parsed = MessageHeader.parseHeader(packet);
		assertEquals(MessageHeaderType.BindingRequest, parsed.getType());
		parsed.parseAttributes(packet);
		assertTrue(parsed.hasMagicCookie());
		assertArrayEquals(RFC5769_HEADER_ID, parsed.getTransactionID());

		Software sw = (Software) parsed.getMessageAttribute(MessageAttributeType.Software);
		assertNotNull(sw);
		assertEquals("STUN test client", sw.getSoftware());

		Priority priority = (Priority) parsed.getMessageAttribute(MessageAttributeType.Priority);
		assertNotNull(priority);
		assertEquals(0x6e0001ffL, priority.getPriority());
		assertArrayEquals(new byte[] {
			(byte) 0x00, (byte) 0x24, (byte) 0x00, (byte) 0x04,
			(byte) 0x6e, (byte) 0x00, (byte) 0x01, (byte) 0xff
		}, priority.getBytes());

		// 0x8029 (ICE-CONTROLLED) is comprehension-optional and must NOT collide with USERHASH (0x001E)
		assertNull(parsed.getMessageAttribute(MessageAttributeType.Userhash));

		Username username = (Username) parsed.getMessageAttribute(MessageAttributeType.Username);
		assertNotNull(username);
		assertEquals("evtj:h6vY", username.getUsername());

		MessageIntegrity parsedMi = (MessageIntegrity) parsed.getMessageAttribute(MessageAttributeType.MessageIntegrity);
		assertNotNull(parsedMi);
		assertArrayEquals(new byte[] {
			(byte) 0x9a, (byte) 0xea, (byte) 0xa7, (byte) 0x0c,
			(byte) 0xbf, (byte) 0xd8, (byte) 0xcb, (byte) 0x56,
			(byte) 0x78, (byte) 0x1e, (byte) 0xf2, (byte) 0xb5,
			(byte) 0xb2, (byte) 0xd3, (byte) 0xf2, (byte) 0x49,
			(byte) 0xc1, (byte) 0xb5, (byte) 0x71, (byte) 0xa2
		}, parsedMi.getHmac());
		assertTrue(MessageHeader.verifyShortTermMessageIntegrity(packet, "VOkJxbRl1RmTxUk/WvJxBt"));
		assertFalse(MessageHeader.verifyShortTermMessageIntegrity(packet, "wrongSecret"));

		Fingerprint fp = (Fingerprint) parsed.getMessageAttribute(MessageAttributeType.Fingerprint);
		assertNotNull(fp);
		assertEquals(0xe57a3bcfL, fp.getCrc());
		assertTrue(Fingerprint.verify(packet));
	}

	@Test
	public void testRfc5769Section2_4_LongTermAuthRequestPacket() throws Exception {
		// Exact 116-byte STUN Binding Request with long-term credentials from RFC 5769 Section 2.4 / Appendix A
		String japaneseUsername = "\u30de\u30c8\u30ea\u30c3\u30af\u30b9";
		String rawPassword = "The\u00adM\u00aatr\u2168";
		String preppedPassword = "TheMatrIX";
		String realm = "example.org";
		String nonce = "f//499k954d6OL34oL9FSTvy64sA";
		byte[] txId = new byte[] {
			(byte) 0x21, (byte) 0x12, (byte) 0xa4, (byte) 0x42,
			(byte) 0x78, (byte) 0xad, (byte) 0x34, (byte) 0x33,
			(byte) 0xc6, (byte) 0xad, (byte) 0x72, (byte) 0xc0,
			(byte) 0x29, (byte) 0xda, (byte) 0x41, (byte) 0x2e
		};

		byte[] packet = new byte[] {
			// Header: BindingRequest (0x0001), length 0x0060 (96 bytes), Magic Cookie, Transaction ID
			(byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x60,
			(byte) 0x21, (byte) 0x12, (byte) 0xa4, (byte) 0x42,
			(byte) 0x78, (byte) 0xad, (byte) 0x34, (byte) 0x33,
			(byte) 0xc6, (byte) 0xad, (byte) 0x72, (byte) 0xc0,
			(byte) 0x29, (byte) 0xda, (byte) 0x41, (byte) 0x2e,
			// USERNAME (0x0006): 18 UTF-8 bytes + 2 NUL padding bytes
			(byte) 0x00, (byte) 0x06, (byte) 0x00, (byte) 0x12,
			(byte) 0xe3, (byte) 0x83, (byte) 0x9e, (byte) 0xe3,
			(byte) 0x83, (byte) 0x88, (byte) 0xe3, (byte) 0x83,
			(byte) 0xaa, (byte) 0xe3, (byte) 0x83, (byte) 0x83,
			(byte) 0xe3, (byte) 0x82, (byte) 0xaf, (byte) 0xe3,
			(byte) 0x82, (byte) 0xb9, (byte) 0x00, (byte) 0x00,
			// NONCE (0x0015): "f//499k954d6OL34oL9FSTvy64sA" (28 bytes)
			(byte) 0x00, (byte) 0x15, (byte) 0x00, (byte) 0x1c,
			(byte) 0x66, (byte) 0x2f, (byte) 0x2f, (byte) 0x34,
			(byte) 0x39, (byte) 0x39, (byte) 0x6b, (byte) 0x39,
			(byte) 0x35, (byte) 0x34, (byte) 0x64, (byte) 0x36,
			(byte) 0x4f, (byte) 0x4c, (byte) 0x33, (byte) 0x34,
			(byte) 0x6f, (byte) 0x4c, (byte) 0x39, (byte) 0x46,
			(byte) 0x53, (byte) 0x54, (byte) 0x76, (byte) 0x79,
			(byte) 0x36, (byte) 0x34, (byte) 0x73, (byte) 0x41,
			// REALM (0x0014): "example.org" (11 bytes) + 1 NUL padding byte
			(byte) 0x00, (byte) 0x14, (byte) 0x00, (byte) 0x0b,
			(byte) 0x65, (byte) 0x78, (byte) 0x61, (byte) 0x6d,
			(byte) 0x70, (byte) 0x6c, (byte) 0x65, (byte) 0x2e,
			(byte) 0x6f, (byte) 0x72, (byte) 0x67, (byte) 0x00,
			// MESSAGE-INTEGRITY (0x0008): HMAC-SHA1 with MD5(username:realm:SASLprep(password))
			(byte) 0x00, (byte) 0x08, (byte) 0x00, (byte) 0x14,
			(byte) 0xf6, (byte) 0x70, (byte) 0x24, (byte) 0x65,
			(byte) 0x6d, (byte) 0xd6, (byte) 0x4a, (byte) 0x3e,
			(byte) 0x02, (byte) 0xb8, (byte) 0xe0, (byte) 0x71,
			(byte) 0x2e, (byte) 0x85, (byte) 0xc9, (byte) 0xa2,
			(byte) 0x8c, (byte) 0xa8, (byte) 0x96, (byte) 0x66
		};
		assertEquals(116, packet.length);

		// 1. Parse the exact RFC 5769 §2.4 wire packet
		MessageHeader parsed = MessageHeader.parseHeader(packet);
		assertEquals(MessageHeaderType.BindingRequest, parsed.getType());
		parsed.parseAttributes(packet);
		assertTrue(parsed.hasMagicCookie());
		assertArrayEquals(txId, parsed.getTransactionID());

		assertEquals(japaneseUsername, ((Username) parsed.getMessageAttribute(MessageAttributeType.Username)).getUsername());
		assertEquals(nonce, ((Nonce) parsed.getMessageAttribute(MessageAttributeType.Nonce)).getNonce());
		assertEquals(realm, ((Realm) parsed.getMessageAttribute(MessageAttributeType.Realm)).getRealm());

		MessageIntegrity parsedMi = (MessageIntegrity) parsed.getMessageAttribute(MessageAttributeType.MessageIntegrity);
		assertNotNull(parsedMi);
		assertArrayEquals(new byte[] {
			(byte) 0xf6, (byte) 0x70, (byte) 0x24, (byte) 0x65,
			(byte) 0x6d, (byte) 0xd6, (byte) 0x4a, (byte) 0x3e,
			(byte) 0x02, (byte) 0xb8, (byte) 0xe0, (byte) 0x71,
			(byte) 0x2e, (byte) 0x85, (byte) 0xc9, (byte) 0xa2,
			(byte) 0x8c, (byte) 0xa8, (byte) 0x96, (byte) 0x66
		}, parsedMi.getHmac());

		// 2. Verify MESSAGE-INTEGRITY with both pre-SASLprep and post-SASLprep RFC 5769 §2.4 passwords
		assertTrue(MessageHeader.verifyLongTermMessageIntegrity(packet, japaneseUsername, realm, rawPassword));
		assertTrue(MessageHeader.verifyLongTermMessageIntegrity(packet, japaneseUsername, realm, preppedPassword));
		assertFalse(MessageHeader.verifyLongTermMessageIntegrity(packet, japaneseUsername, realm, "wrongPassword"));

		// 3. Serialize from scratch and assert exact 116-byte wire equivalence with RFC 5769 §2.4
		MessageHeader built = new MessageHeader(MessageHeaderType.BindingRequest);
		built.setTransactionID(txId);
		built.addMessageAttribute(new Username(japaneseUsername));
		built.addMessageAttribute(new Nonce(nonce));
		built.addMessageAttribute(new Realm(realm));
		byte[] serialized = built.getBytesWithLongTermMessageIntegrity(japaneseUsername, realm, rawPassword);
		assertArrayEquals(packet, serialized);
	}

	@Test
	public void testPriorityAttributeValidationAndRoundTrip() throws Exception {
		Priority def = new Priority();
		assertEquals(0L, def.getPriority());
		def.setPriority(0xFFFFFFFFL);
		assertEquals(0xFFFFFFFFL, def.getPriority());

		byte[] wire = def.getBytes();
		assertEquals(8, wire.length);
		Priority parsed = (Priority) MessageAttribute.parseCommonHeader(wire);
		assertEquals(0xFFFFFFFFL, parsed.getPriority());
		assertEquals(MessageAttributeType.Priority, MessageAttribute.intToType(MessageAttributeInterface.PRIORITY));

		assertThrows(MessageAttributeException.class, () -> new Priority(-1L));
		assertThrows(MessageAttributeException.class, () -> new Priority(0x100000000L));
		assertThrows(MessageAttributeParsingException.class, () -> Priority.parse(null));
		assertThrows(MessageAttributeParsingException.class, () -> Priority.parse(new byte[3]));
		assertThrows(MessageAttributeParsingException.class, () -> Priority.parse(new byte[5]));
	}

	@Test
	public void testSaslPrepRfc4013VectorsAndProhibitedCases() throws Exception {
		// RFC 4013 Section 3 official examples
		assertEquals("IX", SaslPrep.prepare("I\u00adX"));
		assertEquals("user", SaslPrep.prepare("user"));
		assertEquals("USER", SaslPrep.prepare("USER"));
		assertEquals("a", SaslPrep.prepare("\u00aa"));
		assertEquals("IX", SaslPrep.prepare("\u2168"));
		assertEquals("", SaslPrep.prepare(""));

		// RFC 5769 Section 2.4 examples + non-ASCII spaces mapped to ASCII space
		assertEquals("\u30de\u30c8\u30ea\u30c3\u30af\u30b9", SaslPrep.prepare("\u30de\u30c8\u30ea\u30c3\u30af\u30b9"));
		assertEquals("TheMatrIX", SaslPrep.prepare("The\u00adM\u00aatr\u2168"));
		assertEquals("a b c", SaslPrep.prepare("a\u00a0b\u3000c"));
		assertEquals("ab", SaslPrep.prepare("a\u200bb"));

		// Valid pure RandALCat bidirectional string (Arabic letters)
		assertEquals("\u0627\u0628", SaslPrep.prepare("\u0627\u0628"));

		// Prohibited inputs & RFC 4013 §3 error examples
		assertThrows(UtilityException.class, () -> SaslPrep.prepare(null));
		assertThrows(UtilityException.class, () -> SaslPrep.prepare("\u0007"));
		assertThrows(UtilityException.class, () -> SaslPrep.prepare("\u0085"));
		assertThrows(UtilityException.class, () -> SaslPrep.prepare("\uE000"));
		assertThrows(UtilityException.class, () -> SaslPrep.prepare("\uFDD0"));
		assertThrows(UtilityException.class, () -> SaslPrep.prepare("\uFFFD"));
		assertThrows(UtilityException.class, () -> SaslPrep.prepare("\u2FF0"));
		assertThrows(UtilityException.class, () -> SaslPrep.prepare("\u200E"));
		assertThrows(UtilityException.class, () -> SaslPrep.prepare("\uD800"));
		assertThrows(UtilityException.class, () -> SaslPrep.prepare(new String(Character.toChars(0xE0001))));
		assertThrows(UtilityException.class, () -> SaslPrep.prepare("\u0627\u0031"));
		assertThrows(UtilityException.class, () -> SaslPrep.prepare("\u0627a\u0628"));

		// Password that reduces to empty string after SASLprep must be rejected for short-term HMAC
		byte[] dummyHeader = new byte[20];
		assertThrows(UtilityException.class, () -> MessageIntegrity.computeShortTermHMAC(dummyHeader, "\u00ad"));
		assertThrows(UtilityException.class, () -> MessageIntegritySha256.computeShortTermHMAC(dummyHeader, "\u00ad"));
	}
}
