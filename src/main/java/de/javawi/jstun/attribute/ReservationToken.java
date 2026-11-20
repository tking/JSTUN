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

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.util.Utility;
import de.javawi.jstun.util.UtilityException;

/**
 * RESERVATION-TOKEN attribute ({@code 0x0022}) as defined in RFC 5766 §14.9.
 * <p>
 * Contains an 8-byte opaque token identifying a reserved port on the TURN server.
 */
public class ReservationToken extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(ReservationToken.class);
	public static final int TOKEN_LENGTH = 8;
	private byte[] token = new byte[TOKEN_LENGTH];

	public ReservationToken() {
		super(MessageAttributeType.ReservationToken);
	}

	public ReservationToken(byte[] token) throws MessageAttributeException {
		super(MessageAttributeType.ReservationToken);
		setToken(token);
	}

	public byte[] getToken() {
		return Arrays.copyOf(token, TOKEN_LENGTH);
	}

	public void setToken(byte[] token) throws MessageAttributeException {
		if (token == null || token.length != TOKEN_LENGTH) {
			throw new MessageAttributeException("RESERVATION-TOKEN must be exactly 8 bytes");
		}
		this.token = Arrays.copyOf(token, TOKEN_LENGTH);
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		byte[] result = new byte[4 + TOKEN_LENGTH];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(TOKEN_LENGTH), 0, result, 2, 2);
		System.arraycopy(token, 0, result, 4, TOKEN_LENGTH);
		return result;
	}

	public static ReservationToken parse(byte[] data) throws MessageAttributeParsingException {
		try {
			if (data == null || data.length != TOKEN_LENGTH) {
				throw new MessageAttributeParsingException("Invalid length for RESERVATION-TOKEN");
			}
			LOGGER.debug("Message Attribute: ReservationToken parsed (8 bytes).");
			return new ReservationToken(data);
		} catch (MessageAttributeException e) {
			throw new MessageAttributeParsingException("Invalid RESERVATION-TOKEN: " + e.getMessage());
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) return true;
		if (!(obj instanceof ReservationToken)) return false;
		return Arrays.equals(this.token, ((ReservationToken) obj).token);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(token);
	}
}
