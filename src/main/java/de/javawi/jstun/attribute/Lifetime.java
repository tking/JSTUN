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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.util.Utility;
import de.javawi.jstun.util.UtilityException;

/**
 * LIFETIME attribute ({@code 0x000D}) as defined in RFC 5766 §14.2.
 * <p>
 * Represents the duration (in seconds) for which a TURN allocation remains valid.
 */
public class Lifetime extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(Lifetime.class);
	private long lifetimeSeconds;

	public Lifetime() {
		super(MessageAttributeType.Lifetime);
	}

	public Lifetime(long lifetimeSeconds) throws MessageAttributeException {
		super(MessageAttributeType.Lifetime);
		setLifetime(lifetimeSeconds);
	}

	public long getLifetime() {
		return lifetimeSeconds;
	}

	public void setLifetime(long lifetimeSeconds) throws MessageAttributeException {
		if (lifetimeSeconds < 0 || lifetimeSeconds > 0xFFFFFFFFL) {
			throw new MessageAttributeException("LIFETIME out of uint32 range: " + lifetimeSeconds);
		}
		this.lifetimeSeconds = lifetimeSeconds;
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		byte[] result = new byte[8];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(4), 0, result, 2, 2);
		result[4] = (byte) ((lifetimeSeconds >>> 24) & 0xFF);
		result[5] = (byte) ((lifetimeSeconds >>> 16) & 0xFF);
		result[6] = (byte) ((lifetimeSeconds >>> 8) & 0xFF);
		result[7] = (byte) (lifetimeSeconds & 0xFF);
		return result;
	}

	public static Lifetime parse(byte[] data) throws MessageAttributeParsingException {
		try {
			if (data == null || data.length != 4) {
				throw new MessageAttributeParsingException("Invalid length for LIFETIME");
			}
			long seconds = Utility.fourBytesToLong(data);
			Lifetime result = new Lifetime(seconds);
			LOGGER.debug("Message Attribute: Lifetime parsed: {}s.", seconds);
			return result;
		} catch (UtilityException | MessageAttributeException e) {
			throw new MessageAttributeParsingException("Invalid LIFETIME: " + e.getMessage());
		}
	}
}
