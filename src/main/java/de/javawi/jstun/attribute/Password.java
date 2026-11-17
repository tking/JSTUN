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

public class Password extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(Password.class);
	String password;
	
	public Password() {
		super(MessageAttribute.MessageAttributeType.Password);
	}
	
	public Password(String password) {
		super(MessageAttribute.MessageAttributeType.Password);
		setPassword(password);
	}
	
	public String getPassword() {
		return password;
	}
	
	public void setPassword(String password) {
		this.password = password;
	}
	
	public byte[] getBytes() throws UtilityException {
		byte[] temp = (password != null ? password : "").getBytes(StandardCharsets.UTF_8);
		int length = temp.length;
		// password header
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
		
		// password header
		System.arraycopy(temp, 0, result, 4, temp.length);
		return result;
	}
	
	public static Password parse(byte[] data) {
		Password result = new Password();
		int end = data.length;
		while (end > 0 && data[end - 1] == 0) {
			end--;
		}
		String password = new String(data, 0, end, StandardCharsets.UTF_8);
		result.setPassword(password);
		LOGGER.debug("Message Attribute: Password parsed (length={}).", password.length());
		return result;
	}
}