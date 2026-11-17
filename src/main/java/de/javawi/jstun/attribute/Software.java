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

import de.javawi.jstun.util.Utility;
import de.javawi.jstun.util.UtilityException;

public class Software extends MessageAttribute {
	private String software = "";

	public Software() {
		super(MessageAttribute.MessageAttributeType.Software);
	}

	public Software(String software) {
		super(MessageAttribute.MessageAttributeType.Software);
		setSoftware(software);
	}

	public String getSoftware() {
		return software;
	}

	public void setSoftware(String software) {
		this.software = (software != null) ? software : "";
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
		result.setSoftware(new String(data, 0, end, StandardCharsets.UTF_8));
		return result;
	}
}
