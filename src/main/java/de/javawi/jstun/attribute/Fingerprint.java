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

import java.util.zip.CRC32;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.util.Utility;
import de.javawi.jstun.util.UtilityException;

public class Fingerprint extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(Fingerprint.class);
	public static final long FINGERPRINT_XOR_MASK = 0x5354554eL;
	private long crc;

	public Fingerprint() {
		super(MessageAttribute.MessageAttributeType.Fingerprint);
	}

	public Fingerprint(long crc) {
		super(MessageAttribute.MessageAttributeType.Fingerprint);
		this.crc = crc & 0xFFFFFFFFL;
	}

	public long getCrc() {
		return crc;
	}

	public void setCrc(long crc) {
		this.crc = crc & 0xFFFFFFFFL;
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		byte[] result = new byte[8];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(4), 0, result, 2, 2);
		result[4] = (byte) ((crc >>> 24) & 0xFF);
		result[5] = (byte) ((crc >>> 16) & 0xFF);
		result[6] = (byte) ((crc >>> 8) & 0xFF);
		result[7] = (byte) (crc & 0xFF);
		return result;
	}

	public static long calculateFingerprint(byte[] messagePrefixWithoutFingerprint) throws UtilityException {
		if (messagePrefixWithoutFingerprint == null || messagePrefixWithoutFingerprint.length < 20) {
			throw new UtilityException("Message prefix too short for STUN header");
		}
		byte[] copy = new byte[messagePrefixWithoutFingerprint.length];
		System.arraycopy(messagePrefixWithoutFingerprint, 0, copy, 0, messagePrefixWithoutFingerprint.length);
		int adjustedLength = (copy.length - 20) + 8;
		byte[] lenBytes = Utility.integerToTwoBytes(adjustedLength);
		copy[2] = lenBytes[0];
		copy[3] = lenBytes[1];

		CRC32 crc32 = new CRC32();
		crc32.update(copy);
		return (crc32.getValue() ^ FINGERPRINT_XOR_MASK) & 0xFFFFFFFFL;
	}

	public static boolean verify(byte[] fullStunPacket) throws UtilityException, MessageAttributeParsingException {
		if (fullStunPacket == null || fullStunPacket.length < 28) {
			return false;
		}
		int prefixLen = fullStunPacket.length - 8;
		int attrType = ((fullStunPacket[prefixLen] & 0xFF) << 8) | (fullStunPacket[prefixLen + 1] & 0xFF);
		int attrLen = ((fullStunPacket[prefixLen + 2] & 0xFF) << 8) | (fullStunPacket[prefixLen + 3] & 0xFF);
		if (attrType != FINGERPRINT || attrLen != 4) {
			return false;
		}
		byte[] valueBytes = new byte[4];
		System.arraycopy(fullStunPacket, prefixLen + 4, valueBytes, 0, 4);
		Fingerprint parsed = parse(valueBytes);

		byte[] prefix = new byte[prefixLen];
		System.arraycopy(fullStunPacket, 0, prefix, 0, prefixLen);
		long expected = calculateFingerprint(prefix);
		return parsed.getCrc() == expected;
	}

	public static Fingerprint parse(byte[] data) throws MessageAttributeParsingException {
		try {
			if (data.length < 4) {
				throw new MessageAttributeParsingException("Data array too short for Fingerprint");
			}
			long val = Utility.fourBytesToLong(data);
			LOGGER.debug("Message Attribute: Fingerprint parsed: crc=0x{}.", Long.toHexString(val));
			return new Fingerprint(val);
		} catch (UtilityException ue) {
			throw new MessageAttributeParsingException("Parsing error");
		}
	}
}
