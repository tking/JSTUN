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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.util.Address;
import de.javawi.jstun.util.Utility;
import de.javawi.jstun.util.UtilityException;

/**
 * Comprehensive unit tests for STUN attributes (RFC 3489, RFC 5389/8489, RFC 5780)
 * and byte conversion utilities ({@link Utility}, {@link Address}).
 */
public class StunAttributesAndUtilityTest {

	@Test
	public void testUnknownAttributeSingleAndMultipleRoundTrip() throws Exception {
		// Odd count (1 attribute) -> padded to 4 bytes by duplicating the attribute type
		UnknownAttribute uaSingle = new UnknownAttribute();
		uaSingle.addAttribute(MessageAttributeType.Username);
		byte[] singleBytes = uaSingle.getBytes();
		assertEquals(8, singleBytes.length); // 4 header + 4 value
		UnknownAttribute parsedSingle = (UnknownAttribute) MessageAttribute.parseCommonHeader(singleBytes);
		assertNotNull(parsedSingle);
		assertTrue(parsedSingle.getAttributes().contains(MessageAttributeType.Username));

		// Even count (2 attributes) -> 4 bytes value
		UnknownAttribute uaDouble = new UnknownAttribute();
		uaDouble.addAttribute(MessageAttributeType.Username);
		uaDouble.addAttribute(MessageAttributeType.Realm);
		byte[] doubleBytes = uaDouble.getBytes();
		assertEquals(8, doubleBytes.length);
		UnknownAttribute parsedDouble = (UnknownAttribute) MessageAttribute.parseCommonHeader(doubleBytes);
		assertEquals(2, parsedDouble.getAttributes().size());
		assertEquals(MessageAttributeType.Username, parsedDouble.getAttributes().get(0));
		assertEquals(MessageAttributeType.Realm, parsedDouble.getAttributes().get(1));

		// Invalid non-multiple-of-4 data length
		assertThrows(MessageAttributeParsingException.class, () -> UnknownAttribute.parse(new byte[] { 0, 1 }));
	}

	@Test
	public void testErrorCodeAllStandardAndCustomCodes() throws Exception {
		int[] standardCodes = { 300, 400, 401, 420, 430, 431, 432, 433, 438, 500, 600, 487 };
		for (int code : standardCodes) {
			ErrorCode ec = new ErrorCode();
			ec.setResponseCode(code);
			assertEquals(code, ec.getResponseCode());
			assertNotNull(ec.getReason());

			byte[] bytes = ec.getBytes();
			ErrorCode parsed = (ErrorCode) MessageAttribute.parseCommonHeader(bytes);
			assertEquals(code, parsed.getResponseCode());
			assertEquals(ec.getReason(), parsed.getReason());
		}

		// Out of range response codes
		ErrorCode invalid = new ErrorCode();
		assertThrows(MessageAttributeException.class, () -> invalid.setResponseCode(99));
		assertThrows(MessageAttributeException.class, () -> invalid.setResponseCode(700));
		assertThrows(MessageAttributeParsingException.class, () -> ErrorCode.parse(new byte[] { 0, 0 }));
		assertThrows(MessageAttributeParsingException.class, () -> ErrorCode.parse(new byte[] { 0, 0, 7, 0 }));
	}

	@Test
	public void testChangeRequestAllCombinations() throws Exception {
		// 1. Neither
		ChangeRequest cr0 = new ChangeRequest();
		assertFalse(cr0.isChangeIP());
		assertFalse(cr0.isChangePort());
		ChangeRequest parsed0 = (ChangeRequest) MessageAttribute.parseCommonHeader(cr0.getBytes());
		assertFalse(parsed0.isChangeIP());
		assertFalse(parsed0.isChangePort());

		// 2. ChangeIP only
		ChangeRequest crIP = new ChangeRequest();
		crIP.setChangeIP();
		ChangeRequest parsedIP = (ChangeRequest) MessageAttribute.parseCommonHeader(crIP.getBytes());
		assertTrue(parsedIP.isChangeIP());
		assertFalse(parsedIP.isChangePort());

		// 3. ChangePort only
		ChangeRequest crPort = new ChangeRequest();
		crPort.setChangePort();
		ChangeRequest parsedPort = (ChangeRequest) MessageAttribute.parseCommonHeader(crPort.getBytes());
		assertFalse(parsedPort.isChangeIP());
		assertTrue(parsedPort.isChangePort());

		// 4. Both ChangeIP and ChangePort
		ChangeRequest crBoth = new ChangeRequest();
		crBoth.setChangeIP();
		crBoth.setChangePort();
		ChangeRequest parsedBoth = (ChangeRequest) MessageAttribute.parseCommonHeader(crBoth.getBytes());
		assertTrue(parsedBoth.isChangeIP());
		assertTrue(parsedBoth.isChangePort());

		// Invalid data
		assertThrows(MessageAttributeParsingException.class, () -> ChangeRequest.parse(new byte[] { 0, 0 }));
		assertThrows(MessageAttributeParsingException.class, () -> ChangeRequest.parse(new byte[] { 0, 0, 0, 99 }));
	}

	@Test
	public void testMessageIntegrityLongTermAndShortTermAndTamperDetection() throws Exception {
		// RFC 5769 Section 2.4 long-term credentials (UTF-8 Japanese username "マトリックス")
		String japaneseUsername = "\u30de\u30c8\u30ea\u30c3\u30af\u30b9";
		String realm = "example.org";
		String password = "TheMatrIX";

		MessageHeader mh = new MessageHeader(MessageHeaderType.BindingRequest);
		mh.generateTransactionID();
		mh.addMessageAttribute(new Username(japaneseUsername));
		mh.addMessageAttribute(new Realm(realm));
		mh.addMessageAttribute(new Nonce("f//499k954d6OL34oL9FSTvy64sA"));

		byte[] prefix = mh.getBytes();
		byte[] hmac = MessageIntegrity.computeLongTermHMAC(prefix, japaneseUsername, realm, password);
		MessageIntegrity mi = new MessageIntegrity(hmac);
		assertArrayEquals(hmac, mi.getHmac());
		assertTrue(mi.verifyLongTerm(prefix, japaneseUsername, realm, password));
		assertFalse(mi.verifyLongTerm(prefix, japaneseUsername, realm, "wrongPassword"));

		// Short-term credential round-trip
		byte[] shortHmac = MessageIntegrity.computeShortTermHMAC(prefix, "secretKey");
		MessageIntegrity miShort = new MessageIntegrity(shortHmac);
		assertTrue(miShort.verifyShortTerm(prefix, "secretKey"));
		assertFalse(miShort.verifyShortTerm(prefix, "otherKey"));

		// Validation errors
		assertThrows(MessageAttributeException.class, () -> new MessageIntegrity(new byte[10]));
		assertThrows(UtilityException.class, () -> MessageIntegrity.computeShortTermHMAC(new byte[10], "key"));
		assertThrows(MessageAttributeParsingException.class, () -> MessageIntegrity.parse(new byte[10]));
	}

	@Test
	public void testFingerprintCalculationVerificationAndNegativeCases() throws Exception {
		MessageHeader mh = new MessageHeader(MessageHeaderType.BindingRequest);
		mh.generateTransactionID();
		mh.addMessageAttribute(new Software("JSTUN 1.0.0"));

		byte[] prefix = mh.getBytes();
		long crc = Fingerprint.calculateFingerprint(prefix);
		Fingerprint fp = new Fingerprint(crc);
		assertEquals(crc, fp.getCrc());

		mh.addMessageAttribute(fp);
		byte[] fullPacket = mh.getBytes();
		assertTrue(Fingerprint.verify(fullPacket));

		// Tamper with a byte in the header/payload -> verification must return false
		byte[] tampered = fullPacket.clone();
		tampered[20] ^= 0x01;
		assertFalse(Fingerprint.verify(tampered));

		// Too short packet or non-fingerprint trailing attribute -> false
		assertFalse(Fingerprint.verify(new byte[20]));
		assertFalse(Fingerprint.verify(prefix));

		assertThrows(UtilityException.class, () -> Fingerprint.calculateFingerprint(new byte[10]));
		assertThrows(MessageAttributeParsingException.class, () -> Fingerprint.parse(new byte[2]));
	}

	@Test
	public void testStringAttributesWithUnalignedPadding() throws Exception {
		MessageHeader mh = new MessageHeader(MessageHeaderType.BindingRequest);
		mh.generateTransactionID();
		mh.addMessageAttribute(new Username("alice")); // 5 bytes -> padded to 8
		mh.addMessageAttribute(new Password("s3cr3t!")); // 7 bytes -> padded to 8
		mh.addMessageAttribute(new Realm("jstun.org")); // 9 bytes -> padded to 12
		mh.addMessageAttribute(new Nonce("abcde")); // 5 bytes -> padded to 8
		mh.addMessageAttribute(new Software("JSTUN")); // 5 bytes -> padded to 8

		byte[] packet = mh.getBytes();
		MessageHeader parsed = MessageHeader.parseHeader(packet);
		parsed.parseAttributes(packet);

		assertEquals("alice", ((Username) parsed.getMessageAttribute(MessageAttributeType.Username)).getUsername());
		assertEquals("s3cr3t!", ((Password) parsed.getMessageAttribute(MessageAttributeType.Password)).getPassword());
		assertEquals("jstun.org", ((Realm) parsed.getMessageAttribute(MessageAttributeType.Realm)).getRealm());
		assertEquals("abcde", ((Nonce) parsed.getMessageAttribute(MessageAttributeType.Nonce)).getNonce());
		assertEquals("JSTUN", ((Software) parsed.getMessageAttribute(MessageAttributeType.Software)).getSoftware());

		// Dummy attribute
		Dummy dummy = new Dummy();
		dummy.setLengthValue(4);
		assertEquals(8, dummy.getBytes().length);
	}

	@Test
	public void testAddressAttributesIPv4AndIPv6RoundTripThroughMessageHeader() throws Exception {
		MessageHeader mh = new MessageHeader(MessageHeaderType.BindingResponse);
		mh.generateTransactionID();

		AlternateServer as = new AlternateServer();
		as.setAddress(new Address("2001:db8::1"));
		as.setPort(3478);
		mh.addMessageAttribute(as);

		ReflectedFrom rf = new ReflectedFrom();
		rf.setAddress(new Address("198.51.100.9"));
		rf.setPort(12345);
		mh.addMessageAttribute(rf);

		ResponseAddress ra = new ResponseAddress();
		ra.setAddress(new Address("2001:db8::2"));
		ra.setPort(54321);
		mh.addMessageAttribute(ra);

		SourceAddress sa = new SourceAddress();
		sa.setAddress(new Address("192.0.2.10"));
		sa.setPort(3478);
		mh.addMessageAttribute(sa);

		ChangedAddress ca = new ChangedAddress();
		ca.setAddress(new Address("192.0.2.11"));
		ca.setPort(3479);
		mh.addMessageAttribute(ca);

		byte[] packet = mh.getBytes();
		MessageHeader parsed = MessageHeader.parseHeader(packet);
		parsed.parseAttributes(packet);

		AlternateServer parsedAs = (AlternateServer) parsed.getMessageAttribute(MessageAttributeType.AlternateServer);
		assertEquals(new Address("2001:db8:0:0:0:0:0:1"), parsedAs.getAddress());
		assertEquals(new Address("2001:db8::1"), parsedAs.getAddress());
		assertEquals(3478, parsedAs.getPort());

		ReflectedFrom parsedRf = (ReflectedFrom) parsed.getMessageAttribute(MessageAttributeType.ReflectedFrom);
		assertEquals(new Address("198.51.100.9"), parsedRf.getAddress());
		assertEquals(12345, parsedRf.getPort());

		ResponseAddress parsedRa = (ResponseAddress) parsed.getMessageAttribute(MessageAttributeType.ResponseAddress);
		assertEquals(new Address("2001:db8:0:0:0:0:0:2"), parsedRa.getAddress());
		assertEquals(new Address("2001:db8::2"), parsedRa.getAddress());
		assertEquals(54321, parsedRa.getPort());

		// Also test legacy 0x8020 XORMAPPEDADDRESS_OPTIONAL parsing
		XorMappedAddress xma = new XorMappedAddress(mh.getTransactionID());
		xma.setAddress(new Address("203.0.113.99"));
		xma.setPort(40000);
		byte[] xmaBytes = xma.getBytes(mh.getTransactionID());
		xmaBytes[0] = (byte) 0x80;
		xmaBytes[1] = (byte) 0x20;
		XorMappedAddress parsedOpt = (XorMappedAddress) MessageAttribute.parseCommonHeader(xmaBytes, mh.getTransactionID());
		assertEquals(new Address("203.0.113.99"), parsedOpt.getAddress());
		assertEquals(40000, parsedOpt.getPort());
	}

	@Test
	public void testUtilityConversionsAndExceptions() throws Exception {
		assertEquals(255, Utility.oneByteToInteger(Utility.integerToOneByte(255)));
		assertEquals(65535, Utility.twoBytesToInteger(Utility.integerToTwoBytes(65535)));
		assertEquals(0x12345678L, Utility.fourBytesToLong(Utility.integerToFourBytes(0x12345678)));

		assertThrows(UtilityException.class, () -> Utility.integerToOneByte(-1));
		assertThrows(UtilityException.class, () -> Utility.integerToOneByte(100000));
		assertThrows(UtilityException.class, () -> Utility.integerToTwoBytes(-1));
		assertThrows(UtilityException.class, () -> Utility.integerToFourBytes(-1));
		assertThrows(UtilityException.class, () -> Utility.twoBytesToInteger(new byte[1]));
		assertThrows(UtilityException.class, () -> Utility.fourBytesToLong(new byte[3]));
	}

	@Test
	public void testSoftwareRfc5389Compliance() throws Exception {
		Software sw = Software.jstun();
		assertNotNull(sw.getSoftware());
		assertTrue(sw.getSoftware().startsWith("JSTUN/"));
		assertTrue(sw.getSoftware().length() <= Software.MAX_CHARACTERS);

		// 127 characters allowed, 128 characters must throw IllegalArgumentException (RFC 5389 §15.10)
		String maxValid = "a".repeat(Software.MAX_CHARACTERS);
		assertEquals(maxValid, new Software(maxValid).getSoftware());
		String tooLong = "a".repeat(Software.MAX_CHARACTERS + 1);
		assertThrows(IllegalArgumentException.class, () -> new Software(tooLong));
	}
}
