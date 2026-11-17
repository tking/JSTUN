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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.util.JstunVersion;
import de.javawi.jstun.util.Utility;
import de.javawi.jstun.util.UtilityException;

/**
 * SOFTWARE attribute (0x8022) as defined in RFC 5389 §15.10 / RFC 8489 §14.14.
 * <p>
 * The value is a UTF-8 encoded textual description of the software being used by
 * the agent sending the message, which SHOULD include manufacturer and version
 * number. It MUST be fewer than 128 characters.
 */
public class Software extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(Software.class);
	/** RFC 5389 §15.10: the value MUST be fewer than 128 characters. */
	public static final int MAX_CHARACTERS = 127;
	private String software = "";

	public Software() {
		super(MessageAttribute.MessageAttributeType.Software);
	}

	public Software(String software) {
		super(MessageAttribute.MessageAttributeType.Software);
		setSoftware(software);
	}

	/**
	 * Creates the SOFTWARE attribute identifying JSTUN, e.g.
	 * {@code JSTUN/1.0.1 (https://github.com/tking/JSTUN)}.
	 */
	public static Software jstun() {
		return new Software(JstunVersion.SOFTWARE);
	}

	public String getSoftware() {
		return software;
	}

	public void setSoftware(String software) {
		String value = (software != null) ? software : "";
		if (value.codePointCount(0, value.length()) > MAX_CHARACTERS) {
			throw new IllegalArgumentException("SOFTWARE attribute must be fewer than 128 characters (RFC 5389 Section 15.10)");
		}
		this.software = value;
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		byte[] temp = software.getBytes(StandardCharsets.UTF_8);
		int unpaddedLength = temp.length;
		int paddedLength = unpaddedLength;
		if ((paddedLength % 4) != 0) {
			paddedLength += 4 - (paddedLength % 4);
		}
		byte[] result = new byte[4 + paddedLength];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(unpaddedLength), 0, result, 2, 2);
		System.arraycopy(temp, 0, result, 4, temp.length);
		return result;
	}

	public static Software parse(byte[] data) {
		Software result = new Software();
		int end = data.length;
		while (end > 0 && data[end - 1] == 0) {
			end--;
		}
		// Be lenient when parsing values received from remote agents.
		result.software = new String(data, 0, end, StandardCharsets.UTF_8);
		LOGGER.debug("Message Attribute: Software parsed: {}.", result.getSoftware());
		return result;
	}
}
