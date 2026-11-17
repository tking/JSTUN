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

import de.javawi.jstun.util.Utility;
import de.javawi.jstun.util.UtilityException;

public class Username extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(Username.class);
	String username;
	
	public Username() {
		super(MessageAttribute.MessageAttributeType.Username);
	}
	
	public Username(String username) {
		super(MessageAttribute.MessageAttributeType.Username);
		setUsername(username);
	}
	
	public String getUsername() {
		return username;
	}
	
	public void setUsername(String username) {
		this.username = username;
	}
	
	public byte[] getBytes() throws UtilityException {
		byte[] temp = (username != null ? username : "").getBytes(StandardCharsets.UTF_8);
		int length = temp.length;
		// username header
		if ((length % 4) != 0) {
			length += 4 - (length % 4);
		}
		// message attribute header
		length += 4;
		byte[] result = new byte[length];
		// message attribute header
		// type
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		// length
		System.arraycopy(Utility.integerToTwoBytes(temp.length), 0, result, 2, 2);
		
		// username header
		System.arraycopy(temp, 0, result, 4, temp.length);
		return result;
	}
	
	public static Username parse(byte[] data) {
		Username result = new Username();
		int end = data.length;
		while (end > 0 && data[end - 1] == 0) {
			end--;
		}
		String username = new String(data, 0, end, StandardCharsets.UTF_8);
		result.setUsername(username);
		LOGGER.debug("Message Attribute: Username parsed: {}.", username);
		return result;
	}
}
