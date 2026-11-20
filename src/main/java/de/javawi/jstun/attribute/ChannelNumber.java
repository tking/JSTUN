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
 * CHANNEL-NUMBER attribute ({@code 0x000C}) as defined in RFC 5766 §14.1.
 * <p>
 * Valid channel numbers are in the range {@code 0x4000}..{@code 0x7FFF} inclusive.
 */
public class ChannelNumber extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(ChannelNumber.class);
	public static final int MIN_CHANNEL_NUMBER = 0x4000;
	public static final int MAX_CHANNEL_NUMBER = 0x7FFF;

	private int channelNumber = MIN_CHANNEL_NUMBER;

	public ChannelNumber() {
		super(MessageAttributeType.ChannelNumber);
	}

	public ChannelNumber(int channelNumber) throws MessageAttributeException {
		super(MessageAttributeType.ChannelNumber);
		setChannelNumber(channelNumber);
	}

	public int getChannelNumber() {
		return channelNumber;
	}

	public void setChannelNumber(int channelNumber) throws MessageAttributeException {
		if (channelNumber < MIN_CHANNEL_NUMBER || channelNumber > MAX_CHANNEL_NUMBER) {
			throw new MessageAttributeException(
					"CHANNEL-NUMBER out of range (0x4000..0x7FFF): 0x" + Integer.toHexString(channelNumber));
		}
		this.channelNumber = channelNumber;
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		byte[] result = new byte[8];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(4), 0, result, 2, 2);
		System.arraycopy(Utility.integerToTwoBytes(channelNumber), 0, result, 4, 2);
		// bytes 6..7 are RFFU (must be zero)
		return result;
	}

	public static ChannelNumber parse(byte[] data) throws MessageAttributeParsingException {
		try {
			if (data == null || data.length != 4) {
				throw new MessageAttributeParsingException("Invalid length for CHANNEL-NUMBER");
			}
			byte[] chBytes = new byte[] { data[0], data[1] };
			int ch = Utility.twoBytesToInteger(chBytes);
			ChannelNumber result = new ChannelNumber(ch);
			LOGGER.debug("Message Attribute: ChannelNumber parsed: 0x{}.", Integer.toHexString(ch));
			return result;
		} catch (UtilityException | MessageAttributeException e) {
			throw new MessageAttributeParsingException("Invalid CHANNEL-NUMBER: " + e.getMessage());
		}
	}
}
