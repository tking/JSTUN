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

import static org.junit.jupiter.api.Assertions.*;

import java.net.InetAddress;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderException;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.util.Address;
import de.javawi.jstun.util.Utility;
import de.javawi.jstun.util.UtilityException;

public class ExceptionsAndEdgeCasesTest {

	@Test
	public void testExceptionConstructors() {
		UtilityException ue = new UtilityException("util error");
		assertEquals("util error", ue.getMessage());

		MessageAttributeException mae = new MessageAttributeException("attr error");
		assertEquals("attr error", mae.getMessage());

		MessageAttributeParsingException mape = new MessageAttributeParsingException("parse error");
		assertEquals("parse error", mape.getMessage());

		UnknownMessageAttributeException umae = new UnknownMessageAttributeException("unknown", MessageAttributeInterface.MessageAttributeType.Dummy);
		assertEquals("unknown", umae.getMessage());
		assertEquals(MessageAttributeInterface.MessageAttributeType.Dummy, umae.getType());

		MessageHeaderException mhe = new MessageHeaderException("hdr error");
		assertEquals("hdr error", mhe.getMessage());

		MessageHeaderParsingException mhpe = new MessageHeaderParsingException("hdr parse error");
		assertEquals("hdr parse error", mhpe.getMessage());
	}

	@Test
	public void testMessageHeaderNegativeAndEdgeCases() throws Exception {
		// parseHeader data too short
		assertThrows(MessageHeaderParsingException.class, () -> MessageHeader.parseHeader(new byte[1]));

		// parseHeader with unsupported message type (e.g. 0x9999)
		byte[] invalidType = new byte[20];
		invalidType[0] = (byte) 0x99;
		invalidType[1] = (byte) 0x99;
		assertThrows(MessageHeaderParsingException.class, () -> MessageHeader.parseHeader(invalidType));

		// parseAttributes with data array too short
		MessageHeader mh = new MessageHeader(MessageHeaderType.BindingRequest);
		assertThrows(MessageAttributeParsingException.class, () -> mh.parseAttributes(new byte[19]));

		// parseAttributes with indicated length larger than available bytes
		byte[] corruptedLen = new byte[24];
		corruptedLen[2] = 0x00;
		corruptedLen[3] = 0x20; // indicates 32 attribute bytes, but only 4 bytes follow header
		assertThrows(MessageAttributeParsingException.class, () -> mh.parseAttributes(corruptedLen));

		// equalTransactionID comparison edge cases
		MessageHeader mh1 = new MessageHeader();
		mh1.generateTransactionID();
		MessageHeader mh2 = new MessageHeader();
		mh2.generateTransactionID();
		assertFalse(mh1.equalTransactionID(mh2));

		// equalTransactionID with modified byte
		byte[] idCopy = mh1.getTransactionID();
		idCopy[15] ^= 0x01;
		mh2.setTransactionID(idCopy);
		assertFalse(mh1.equalTransactionID(mh2));

		// RFC 3489 Transaction ID generation (random 16 bytes, does not guarantee magic cookie)
		MessageHeader mhRfc3489 = new MessageHeader();
		mhRfc3489.generateRFC3489TransactionID();
		assertEquals(16, mhRfc3489.getTransactionID().length);

		// RFC 5389 Transaction ID has magic cookie
		MessageHeader mhRfc5389 = new MessageHeader();
		mhRfc5389.generateTransactionID();
		assertTrue(mhRfc5389.hasMagicCookie());
	}

	@Test
	public void testErrorCodeValidationAndParsing() throws Exception {
		ErrorCode ec = new ErrorCode();

		// Negative: ResponseCode < 100 or > 699 throws MessageAttributeException
		assertThrows(MessageAttributeException.class, () -> ec.setResponseCode(99));
		assertThrows(MessageAttributeException.class, () -> ec.setResponseCode(700));

		// Valid standard codes
		ec.setResponseCode(300);
		assertEquals("Try Alternate", ec.getReason());
		ec.setResponseCode(400);
		assertEquals("Bad Request", ec.getReason());
		ec.setResponseCode(401);
		assertEquals("Unauthorized", ec.getReason());
		ec.setResponseCode(420);
		assertEquals("Unkown Attribute", ec.getReason());
		ec.setResponseCode(430);
		assertEquals("Stale Credentials", ec.getReason());
		ec.setResponseCode(431);
		assertEquals("Integrity Check Failure", ec.getReason());
		ec.setResponseCode(432);
		assertEquals("Missing Username", ec.getReason());
		ec.setResponseCode(433);
		assertEquals("Use TLS", ec.getReason());
		ec.setResponseCode(438);
		assertEquals("Stale Nonce", ec.getReason());
		ec.setResponseCode(500);
		assertEquals("Server Error", ec.getReason());
		ec.setResponseCode(600);
		assertEquals("Global Failure", ec.getReason());

		// Custom unmapped valid code (e.g. 450)
		ec.setResponseCode(450);
		assertEquals("Error 450", ec.getReason());

		// Custom reason override
		ec.setReason("Custom Reason");
		assertEquals("Custom Reason", ec.getReason());

		// Round-trip serialization & parsing
		byte[] bytes = ec.getBytes();
		byte[] valueBytes = new byte[bytes.length - 4];
		System.arraycopy(bytes, 4, valueBytes, 0, valueBytes.length);
		ErrorCode parsed = ErrorCode.parse(valueBytes);
		assertEquals(450, parsed.getResponseCode());
		assertEquals("Custom Reason", parsed.getReason());

		// Parsing with truncated bytes
		assertThrows(MessageAttributeParsingException.class, () -> ErrorCode.parse(new byte[3]));
	}

	@Test
	public void testMessageAttributeComprehensionRules() throws Exception {
		byte[] tid = new byte[16];

		// Unknown comprehension-required attribute (type <= 0x7FFF, e.g. 0x007F)
		byte[] requiredUnknown = new byte[8];
		requiredUnknown[0] = 0x00;
		requiredUnknown[1] = 0x7F;
		requiredUnknown[2] = 0x00;
		requiredUnknown[3] = 0x04; // length 4
		assertThrows(UnknownMessageAttributeException.class, () -> {
			MessageAttribute.parseCommonHeader(requiredUnknown, tid);
		});

		// Unknown comprehension-optional attribute (type > 0x7FFF, e.g. 0x807F) -> Dummy attribute
		byte[] optionalUnknown = new byte[8];
		optionalUnknown[0] = (byte) 0x80;
		optionalUnknown[1] = 0x7F;
		optionalUnknown[2] = 0x00;
		optionalUnknown[3] = 0x04; // length 4
		MessageAttribute attr = MessageAttribute.parseCommonHeader(optionalUnknown, tid);
		assertNotNull(attr);
		assertTrue(attr instanceof Dummy);
	}

	@Test
	public void testAddressEdgeCasesAndValidation() throws Exception {
		// Null and invalid IP string
		assertThrows(UtilityException.class, () -> new Address((String) null));
		assertThrows(UtilityException.class, () -> new Address(""));
		assertThrows(UtilityException.class, () -> new Address("not.an.ip.address"));
		assertThrows(UtilityException.class, () -> new Address("999.999.999.999"));
		assertThrows(UtilityException.class, () -> new Address("1.2.3"));
		assertThrows(UtilityException.class, () -> new Address("1.2.3.4.5"));

		// Invalid int octets
		assertThrows(UtilityException.class, () -> new Address(-1, 0, 0, 0));
		assertThrows(UtilityException.class, () -> new Address(256, 0, 0, 0));
		assertThrows(UtilityException.class, () -> new Address(new int[] { 1, 2, 3 }));
		assertThrows(UtilityException.class, () -> new Address(new int[] { 1, 2, -1, 4 }));

		// Invalid byte array lengths (neither 4 nor 16)
		assertThrows(UtilityException.class, () -> new Address(new byte[0]));
		assertThrows(UtilityException.class, () -> new Address(new byte[5]));
		assertThrows(UtilityException.class, () -> new Address(new byte[15]));
		assertThrows(UtilityException.class, () -> new Address(new byte[17]));

		// Valid address and equals / hashCode
		Address addr1 = new Address("127.0.0.1");
		Address same = new Address(new byte[] { 127, 0, 0, 1 });
		assertEquals(addr1, same);
		assertEquals(addr1.hashCode(), same.hashCode());
		assertEquals("127.0.0.1", addr1.toString());
		assertNotNull(addr1.getInetAddress());
		assertNotNull(addr1.getBytes());

		Address diff = new Address("127.0.0.2");
		assertFalse(addr1.equals(diff));
		assertFalse(addr1.equals(null));
		assertFalse(addr1.equals("otherObject"));
	}

	@Test
	public void testUtilityEdgeCases() {
		// twoBytesToInteger validation
		assertThrows(UtilityException.class, () -> Utility.twoBytesToInteger(new byte[1]));

		// fourBytesToLong validation
		assertThrows(UtilityException.class, () -> Utility.fourBytesToLong(new byte[3]));

		// integerToOneByte validation (value < 0)
		assertThrows(UtilityException.class, () -> Utility.integerToOneByte(-1));

		// integerToTwoBytes validation (value < 0)
		assertThrows(UtilityException.class, () -> Utility.integerToTwoBytes(-1));

		// integerToFourBytes validation (value < 0)
		assertThrows(UtilityException.class, () -> Utility.integerToFourBytes(-1));
	}

	@Test
	public void testXorMappedAddressAndBaseAddressEdgeCases() throws Exception {
		// setTransactionID with null, 12-byte, 16-byte, and <12-byte arrays
		XorMappedAddress xma = new XorMappedAddress();
		xma.setTransactionID(null);
		byte[] tx12 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
		xma.setTransactionID(tx12);
		byte[] copy = xma.getTransactionID();
		assertArrayEquals(tx12, copy);
		copy[0] ^= 0xFF; // defensive copy check
		assertArrayEquals(tx12, xma.getTransactionID());

		byte[] tx16 = new byte[] { 0x21, 0x12, (byte) 0xA4, 0x42, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
		xma.setTransactionID(tx16);
		assertEquals(12, xma.getTransactionID()[0]);

		// Short array (< 12 bytes) is ignored without throwing
		xma.setTransactionID(new byte[] { 99, 98, 97 });
		assertEquals(12, xma.getTransactionID()[0]);

		// IPv4 round-trip via parse(byte[]) without transaction ID
		xma.setAddress(new Address("192.0.2.1"));
		xma.setPort(32853);
		byte[] wireV4 = xma.getBytes();
		byte[] valV4 = java.util.Arrays.copyOfRange(wireV4, 4, wireV4.length);
		XorMappedAddress parsedV4 = (XorMappedAddress) XorMappedAddress.parse(valV4);
		assertEquals(new Address("192.0.2.1"), parsedV4.getAddress());
		assertEquals(32853, parsedV4.getPort());

		// IPv6 round-trip via getBytes(tx16) and parse(val, tx16)
		xma.setAddress(new Address("2001:db8::1"));
		xma.setPort(54321);
		byte[] wireV6 = xma.getBytes(tx16);
		byte[] valV6 = java.util.Arrays.copyOfRange(wireV6, 4, wireV6.length);
		XorMappedAddress parsedV6 = (XorMappedAddress) XorMappedAddress.parse(valV6, tx16);
		assertEquals(new Address("2001:db8::1"), parsedV6.getAddress());
		assertEquals(54321, parsedV6.getPort());

		// XorMappedAddress.parse error branches
		assertThrows(MessageAttributeParsingException.class, () -> XorMappedAddress.parse(new byte[7]));
		byte[] badFamily = new byte[] { 0x00, 0x03, 0x00, 0x50, 1, 2, 3, 4 };
		assertThrows(MessageAttributeParsingException.class, () -> XorMappedAddress.parse(badFamily));
		byte[] truncatedV6 = new byte[12];
		truncatedV6[1] = 0x02;
		assertThrows(MessageAttributeParsingException.class, () -> XorMappedAddress.parse(truncatedV6, tx12));

		// MappedResponseChangedSourceAddressReflectedFrom defaults, port bounds, and parsing errors
		MappedResponseChangedSourceAddressReflectedFrom base = new MappedResponseChangedSourceAddressReflectedFrom();
		assertEquals(0, base.getPort());
		assertEquals(new Address("0.0.0.0"), base.getAddress());
		assertTrue(base.toString().contains("0.0.0.0"));
		base.setPort(0);
		base.setPort(65535);
		assertEquals(65535, base.getPort());
		assertThrows(MessageAttributeException.class, () -> base.setPort(-1));
		assertThrows(MessageAttributeException.class, () -> base.setPort(65537));
		assertThrows(MessageAttributeParsingException.class, () -> MappedAddress.parse(new byte[7]));
		assertThrows(MessageAttributeParsingException.class, () -> MappedAddress.parse(badFamily));
	}

	@Test
	public void testMessageAttributeAndHeaderMappingsAndFingerprintReplacement() throws Exception {
		// Round-trip every MessageAttributeType
		for (MessageAttributeInterface.MessageAttributeType type : MessageAttributeInterface.MessageAttributeType.values()) {
			int code = MessageAttribute.typeToInteger(type);
			assertTrue(code >= 0, "Expected non-negative code for " + type);
			assertEquals(type, MessageAttribute.intToType(code), "Round-trip mismatch for " + type);
		}
		assertEquals(-1, MessageAttribute.typeToInteger(null));
		assertNull(MessageAttribute.intToType(0x9999));
		assertEquals(MessageAttributeInterface.MessageAttributeType.XorMappedAddress,
				MessageAttribute.intToType(MessageAttributeInterface.XORMAPPEDADDRESS_OPTIONAL));

		// MessageHeader null/shared-secret/fingerprint replacement coverage
		assertThrows(MessageHeaderParsingException.class, () -> MessageHeader.parseHeader(null));
		assertEquals(-1, MessageHeader.typeToInteger(null));

		for (MessageHeaderType hdrType : MessageHeaderType.values()) {
			MessageHeader h = new MessageHeader(hdrType);
			h.generateTransactionID();
			byte[] raw = h.getBytes();
			MessageHeader parsed = MessageHeader.parseHeader(raw);
			assertEquals(hdrType, parsed.getType());
		}

		// getBytesWithFingerprint when a Fingerprint attribute is already attached
		MessageHeader mh = new MessageHeader(MessageHeaderType.BindingRequest);
		mh.generateTransactionID();
		mh.addMessageAttribute(Software.jstun());
		Fingerprint placeholder = new Fingerprint(0x12345678L);
		mh.addMessageAttribute(placeholder);
		byte[] wireWithFp = mh.getBytesWithFingerprint();
		assertTrue(Fingerprint.verify(wireWithFp));
		// Original placeholder must be restored in finally
		assertSame(placeholder, mh.getMessageAttribute(MessageAttributeInterface.MessageAttributeType.Fingerprint));
	}
}
