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

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.util.Utility;
import de.javawi.jstun.util.UtilityException;

public class MessageIntegrity extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(MessageIntegrity.class);
	private byte[] hmac = new byte[20];

	public MessageIntegrity() {
		super(MessageAttribute.MessageAttributeType.MessageIntegrity);
	}

	public MessageIntegrity(byte[] hmac) throws MessageAttributeException {
		super(MessageAttribute.MessageAttributeType.MessageIntegrity);
		setHmac(hmac);
	}

	public byte[] getHmac() {
		byte[] copy = new byte[hmac.length];
		System.arraycopy(hmac, 0, copy, 0, hmac.length);
		return copy;
	}

	public void setHmac(byte[] hmac) throws MessageAttributeException {
		if (hmac == null || hmac.length != 20) {
			throw new MessageAttributeException("HMAC-SHA1 must be 20 bytes");
		}
		System.arraycopy(hmac, 0, this.hmac, 0, 20);
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		byte[] result = new byte[24];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(20), 0, result, 2, 2);
		System.arraycopy(hmac, 0, result, 4, 20);
		return result;
	}

	public static byte[] computeShortTermHMAC(byte[] messagePrefixWithoutIntegrity, String password)
			throws UtilityException {
		if (password == null || password.isEmpty()) {
			throw new UtilityException("HMAC password must not be null or empty");
		}
		return computeHMAC(messagePrefixWithoutIntegrity, password.getBytes(StandardCharsets.UTF_8));
	}

	public static byte[] computeLongTermHMAC(byte[] messagePrefixWithoutIntegrity, String username, String realm,
			String password) throws UtilityException {
		try {
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			String credentials = username + ":" + realm + ":" + password;
			byte[] key = md5.digest(credentials.getBytes(StandardCharsets.UTF_8));
			return computeHMAC(messagePrefixWithoutIntegrity, key);
		} catch (GeneralSecurityException gse) {
			throw new UtilityException("Failed to compute MD5 key for long-term credentials: " + gse.getMessage());
		}
	}

	public static byte[] computeHMAC(byte[] messagePrefixWithoutIntegrity, byte[] key) throws UtilityException {
		if (messagePrefixWithoutIntegrity == null || messagePrefixWithoutIntegrity.length < 20) {
			throw new UtilityException("Message prefix too short for STUN header");
		}
		if (key == null || key.length == 0) {
			throw new UtilityException("HMAC key must not be null or empty");
		}
		try {
			byte[] copy = new byte[messagePrefixWithoutIntegrity.length];
			System.arraycopy(messagePrefixWithoutIntegrity, 0, copy, 0, messagePrefixWithoutIntegrity.length);
			int adjustedLength = (copy.length - 20) + 24;
			byte[] lenBytes = Utility.integerToTwoBytes(adjustedLength);
			copy[2] = lenBytes[0];
			copy[3] = lenBytes[1];

			Mac mac = Mac.getInstance("HmacSHA1");
			SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA1");
			mac.init(keySpec);
			return mac.doFinal(copy);
		} catch (GeneralSecurityException gse) {
			throw new UtilityException("Failed to compute HMAC-SHA1: " + gse.getMessage());
		}
	}

	public boolean verifyShortTerm(byte[] messagePrefixWithoutIntegrity, String password) throws UtilityException {
		byte[] expected = computeShortTermHMAC(messagePrefixWithoutIntegrity, password);
		return MessageDigest.isEqual(this.hmac, expected);
	}

	public boolean verifyLongTerm(byte[] messagePrefixWithoutIntegrity, String username, String realm, String password)
			throws UtilityException {
		byte[] expected = computeLongTermHMAC(messagePrefixWithoutIntegrity, username, realm, password);
		return MessageDigest.isEqual(this.hmac, expected);
	}

	public static MessageIntegrity parse(byte[] data) throws MessageAttributeParsingException {
		if (data == null || data.length != 20) {
			throw new MessageAttributeParsingException(
					"Invalid length for MessageIntegrity: " + (data == null ? "null" : data.length));
		}
		MessageIntegrity mi = new MessageIntegrity();
		System.arraycopy(data, 0, mi.hmac, 0, 20);
		LOGGER.debug("Message Attribute: Message Integrity parsed (20-byte HMAC-SHA1).");
		return mi;
	}
}
