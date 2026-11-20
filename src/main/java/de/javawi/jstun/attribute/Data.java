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
 * DATA attribute ({@code 0x0013}) as defined in RFC 5766 §14.4.
 * <p>
 * Carries opaque application payload bytes in TURN {@code Send} and {@code Data}
 * indications, padded to a 4-byte boundary on the wire while preserving the
 * exact unpadded payload length (including any trailing zero bytes).
 */
public class Data extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(Data.class);
	private byte[] data = new byte[0];

	public Data() {
		super(MessageAttributeType.Data);
	}

	public Data(byte[] data) {
		super(MessageAttributeType.Data);
		setData(data);
	}

	public byte[] getData() {
		return Arrays.copyOf(data, data.length);
	}

	public void setData(byte[] data) {
		this.data = (data != null) ? Arrays.copyOf(data, data.length) : new byte[0];
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		int unpadded = data.length;
		int padded = unpadded;
		if ((padded % 4) != 0) {
			padded += 4 - (padded % 4);
		}
		byte[] result = new byte[4 + padded];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(unpadded), 0, result, 2, 2);
		System.arraycopy(data, 0, result, 4, unpadded);
		return result;
	}

	public static Data parse(byte[] data) {
		Data result = new Data(data);
		LOGGER.debug("Message Attribute: Data parsed ({} bytes).", result.data.length);
		return result;
	}
}
