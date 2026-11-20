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
 * DONT-FRAGMENT attribute ({@code 0x001A}) as defined in RFC 5766 §14.8.
 * <p>
 * Zero-length flag attribute (4 bytes total on the wire).
 */
public class DontFragment extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(DontFragment.class);

	public DontFragment() {
		super(MessageAttributeType.DontFragment);
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		byte[] result = new byte[4];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		// length is 0 (bytes 2..3 already zero)
		return result;
	}

	public static DontFragment parse(byte[] data) throws MessageAttributeParsingException {
		if (data != null && data.length != 0) {
			throw new MessageAttributeParsingException("DONT-FRAGMENT must have length 0, actual " + data.length);
		}
		LOGGER.debug("Message Attribute: DontFragment parsed.");
		return new DontFragment();
	}
}
