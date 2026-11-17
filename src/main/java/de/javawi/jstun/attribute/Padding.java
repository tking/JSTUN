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

public class Padding extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(Padding.class);
	private byte[] paddingBytes = new byte[4];

	public Padding() {
		super(MessageAttribute.MessageAttributeType.Padding);
	}

	public Padding(int length) {
		super(MessageAttribute.MessageAttributeType.Padding);
		setPaddingLength(length);
	}

	public void setPaddingLength(int length) {
		int padded = Math.max(0, length);
		if ((padded % 4) != 0) {
			padded += 4 - (padded % 4);
		}
		this.paddingBytes = new byte[padded];
	}

	public int getPaddingLength() {
		return paddingBytes.length;
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		int len = paddingBytes.length;
		if ((len % 4) != 0) {
			len += 4 - (len % 4);
		}
		byte[] result = new byte[4 + len];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(len), 0, result, 2, 2);
		System.arraycopy(paddingBytes, 0, result, 4, paddingBytes.length);
		return result;
	}

	public static Padding parse(byte[] data) {
		Padding p = new Padding();
		p.paddingBytes = new byte[data.length];
		System.arraycopy(data, 0, p.paddingBytes, 0, data.length);
		LOGGER.debug("Message Attribute: Padding parsed (length={}).", data.length);
		return p;
	}
}
