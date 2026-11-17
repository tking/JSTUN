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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.util.Utility;
import de.javawi.jstun.util.UtilityException;

/**
 * USERHASH attribute (0x8029) as defined in RFC 8489 §14.4.
 * <p>
 * Contains the 32-byte SHA-256 hash of {@code username ":" realm} for
 * privacy-preserving long-term credential authentication.
 */
public class Userhash extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(Userhash.class);
	public static final int HASH_LENGTH = 32;
	private byte[] hash = new byte[HASH_LENGTH];

	public Userhash() {
		super(MessageAttribute.MessageAttributeType.Userhash);
	}

	public Userhash(byte[] hash) throws MessageAttributeException {
		super(MessageAttribute.MessageAttributeType.Userhash);
		setHash(hash);
	}

	public Userhash(String username, String realm) throws UtilityException {
		super(MessageAttribute.MessageAttributeType.Userhash);
		this.hash = computeUserhash(username, realm);
	}

	public byte[] getHash() {
		byte[] copy = new byte[HASH_LENGTH];
		System.arraycopy(hash, 0, copy, 0, HASH_LENGTH);
		return copy;
	}

	public void setHash(byte[] hash) throws MessageAttributeException {
		if (hash == null || hash.length != HASH_LENGTH) {
			throw new MessageAttributeException("USERHASH must be exactly 32 bytes");
		}
		this.hash = new byte[HASH_LENGTH];
		System.arraycopy(hash, 0, this.hash, 0, HASH_LENGTH);
	}

	public static byte[] computeUserhash(String username, String realm) throws UtilityException {
		try {
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			String input = (username != null ? username : "") + ":" + (realm != null ? realm : "");
			return sha256.digest(input.getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException e) {
			throw new UtilityException("SHA-256 algorithm not available");
		}
	}

	public boolean matches(String username, String realm) throws UtilityException {
		return MessageDigest.isEqual(this.hash, computeUserhash(username, realm));
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		byte[] result = new byte[4 + HASH_LENGTH];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(HASH_LENGTH), 0, result, 2, 2);
		System.arraycopy(hash, 0, result, 4, HASH_LENGTH);
		return result;
	}

	public static Userhash parse(byte[] data) throws MessageAttributeParsingException {
		try {
			if (data.length != HASH_LENGTH) {
				throw new MessageAttributeParsingException("Invalid length for USERHASH: " + data.length);
			}
			LOGGER.debug("Message Attribute: Userhash parsed (32-byte SHA-256).");
			return new Userhash(Arrays.copyOf(data, HASH_LENGTH));
		} catch (MessageAttributeException mae) {
			throw new MessageAttributeParsingException("Parsing error");
		}
	}
}
