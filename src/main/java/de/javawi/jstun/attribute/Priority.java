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
 * PRIORITY attribute ({@code 0x0024}) as defined in RFC 5245 §19.1 / RFC 8445 §16.1.
 * <p>
 * Carries an unsigned 32-bit integer indicating the priority that is to be
 * associated with a peer-reflexive candidate during ICE connectivity checks.
 */
public class Priority extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(Priority.class);
	private long priority;

	public Priority() {
		super(MessageAttributeType.Priority);
	}

	public Priority(long priority) throws MessageAttributeException {
		super(MessageAttributeType.Priority);
		setPriority(priority);
	}

	public long getPriority() {
		return priority;
	}

	public void setPriority(long priority) throws MessageAttributeException {
		if (priority < 0 || priority > 0xFFFFFFFFL) {
			throw new MessageAttributeException("PRIORITY out of uint32 range: " + priority);
		}
		this.priority = priority;
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		byte[] result = new byte[8];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(4), 0, result, 2, 2);
		result[4] = (byte) ((priority >>> 24) & 0xFF);
		result[5] = (byte) ((priority >>> 16) & 0xFF);
		result[6] = (byte) ((priority >>> 8) & 0xFF);
		result[7] = (byte) (priority & 0xFF);
		return result;
	}

	public static Priority parse(byte[] data) throws MessageAttributeParsingException {
		try {
			if (data == null || data.length != 4) {
				throw new MessageAttributeParsingException("Invalid length for PRIORITY");
			}
			long value = Utility.fourBytesToLong(data);
			Priority result = new Priority(value);
			LOGGER.debug("Message Attribute: Priority parsed: {}.", value);
			return result;
		} catch (UtilityException | MessageAttributeException e) {
			throw new MessageAttributeParsingException("Invalid PRIORITY: " + e.getMessage());
		}
	}
}
