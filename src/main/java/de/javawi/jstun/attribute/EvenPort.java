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
 * EVEN-PORT attribute ({@code 0x0018}) as defined in RFC 5766 §14.6.
 * <p>
 * 1-byte value where the most significant bit ({@code 0x80}) is the {@code R}
 * flag requesting reservation of the next-higher odd port, padded to 4 bytes on
 * the wire (header length = {@code 1}, total wire length = {@code 8} bytes).
 */
public class EvenPort extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(EvenPort.class);
	private boolean reserveNextPort;

	public EvenPort() {
		super(MessageAttributeType.EvenPort);
	}

	public EvenPort(boolean reserveNextPort) {
		super(MessageAttributeType.EvenPort);
		this.reserveNextPort = reserveNextPort;
	}

	public boolean isReserveNextPort() {
		return reserveNextPort;
	}

	public void setReserveNextPort(boolean reserveNextPort) {
		this.reserveNextPort = reserveNextPort;
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		byte[] result = new byte[8];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(1), 0, result, 2, 2);
		result[4] = reserveNextPort ? (byte) 0x80 : 0x00;
		return result;
	}

	public static EvenPort parse(byte[] data) throws MessageAttributeParsingException {
		if (data == null || data.length != 1) {
			throw new MessageAttributeParsingException("Invalid length for EVEN-PORT");
		}
		boolean reserve = (data[0] & 0x80) != 0;
		LOGGER.debug("Message Attribute: EvenPort parsed: reserveNextPort={}.", reserve);
		return new EvenPort(reserve);
	}
}
