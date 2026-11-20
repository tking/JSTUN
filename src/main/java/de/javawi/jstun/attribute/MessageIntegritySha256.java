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
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.util.SaslPrep;
import de.javawi.jstun.util.Utility;
import de.javawi.jstun.util.UtilityException;

/**
 * MESSAGE-INTEGRITY-SHA256 attribute (0x001C) as defined in RFC 8489 §14.6.
 * <p>
 * Contains a 32-byte HMAC-SHA256 over the STUN message (with header length
 * adjusted to include this 36-byte attribute).
 */
public class MessageIntegritySha256 extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(MessageIntegritySha256.class);
	public static final int HMAC_LENGTH = 32;
	private byte[] hmac = new byte[HMAC_LENGTH];

	public MessageIntegritySha256() {
		super(MessageAttribute.MessageAttributeType.MessageIntegritySha256);
	}

	public MessageIntegritySha256(byte[] hmac) throws MessageAttributeException {
		super(MessageAttribute.MessageAttributeType.MessageIntegritySha256);
		setHmac(hmac);
	}

	public byte[] getHmac() {
		byte[] copy = new byte[HMAC_LENGTH];
		System.arraycopy(hmac, 0, copy, 0, HMAC_LENGTH);
		return copy;
	}

	public void setHmac(byte[] hmac) throws MessageAttributeException {
		if (hmac == null || hmac.length != HMAC_LENGTH) {
			throw new MessageAttributeException("MESSAGE-INTEGRITY-SHA256 must be exactly 32 bytes");
		}
		this.hmac = new byte[HMAC_LENGTH];
		System.arraycopy(hmac, 0, this.hmac, 0, HMAC_LENGTH);
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		byte[] result = new byte[4 + HMAC_LENGTH];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(HMAC_LENGTH), 0, result, 2, 2);
		System.arraycopy(hmac, 0, result, 4, HMAC_LENGTH);
		return result;
	}

	public static byte[] computeShortTermHMAC(byte[] messagePrefixWithoutIntegrity, String password)
			throws UtilityException {
		if (password == null || password.isEmpty()) {
			throw new UtilityException("HMAC password must not be null or empty");
		}
		String preparedPassword = SaslPrep.prepare(password);
		if (preparedPassword.isEmpty()) {
			throw new UtilityException("HMAC password must not be empty after SASLprep");
		}
		byte[] key = preparedPassword.getBytes(StandardCharsets.UTF_8);
		return computeHMAC(messagePrefixWithoutIntegrity, key);
	}

	public static byte[] computeLongTermHMAC(byte[] messagePrefixWithoutIntegrity, String username, String realm,
			String password) throws UtilityException {
		byte[] key = computeLongTermKey(username, realm, password);
		return computeHMAC(messagePrefixWithoutIntegrity, key);
	}

	/**
	 * Computes the RFC 8489 §9.2.2 SHA-256 long-term credential key:
	 * {@code SHA-256(username ":" realm ":" password)} after RFC 4013 SASLprep.
	 */
	public static byte[] computeLongTermKey(String username, String realm, String password) throws UtilityException {
		try {
			String preparedUsername = username != null ? SaslPrep.prepare(username) : "";
			String preparedRealm = realm != null ? SaslPrep.prepare(realm) : "";
			String preparedPassword = password != null ? SaslPrep.prepare(password) : "";
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			String input = preparedUsername + ":" + preparedRealm + ":" + preparedPassword;
			return sha256.digest(input.getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException e) {
			throw new UtilityException("SHA-256 algorithm not available");
		}
	}

	public static byte[] computeHMAC(byte[] messagePrefixWithoutIntegrity, byte[] key) throws UtilityException {
		if (messagePrefixWithoutIntegrity == null || messagePrefixWithoutIntegrity.length < 20) {
			throw new UtilityException("Message prefix too short for STUN header");
		}
		if (key == null || key.length == 0) {
			throw new UtilityException("HMAC key must not be null or empty");
		}
		byte[] copy = new byte[messagePrefixWithoutIntegrity.length];
		System.arraycopy(messagePrefixWithoutIntegrity, 0, copy, 0, messagePrefixWithoutIntegrity.length);
		int adjustedLength = (copy.length - 20) + 4 + HMAC_LENGTH;
		byte[] lenBytes = Utility.integerToTwoBytes(adjustedLength);
		copy[2] = lenBytes[0];
		copy[3] = lenBytes[1];

		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(new SecretKeySpec(key, "HmacSHA256"));
			return mac.doFinal(copy);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new UtilityException("Failed to compute HmacSHA256: " + e.getMessage());
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

	public static MessageIntegritySha256 parse(byte[] data) throws MessageAttributeParsingException {
		try {
			if (data == null || data.length != HMAC_LENGTH) {
				throw new MessageAttributeParsingException(
						"Invalid length for MESSAGE-INTEGRITY-SHA256: " + (data == null ? "null" : data.length));
			}
			LOGGER.debug("Message Attribute: Message Integrity SHA-256 parsed (32-byte HMAC-SHA256).");
			return new MessageIntegritySha256(Arrays.copyOf(data, HMAC_LENGTH));
		} catch (MessageAttributeException mae) {
			throw new MessageAttributeParsingException("Parsing error");
		}
	}
}
