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

public class ResponsePort extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(ResponsePort.class);
	private int port;

	public ResponsePort() {
		super(MessageAttribute.MessageAttributeType.ResponsePort);
	}

	public ResponsePort(int port) throws MessageAttributeException {
		super(MessageAttribute.MessageAttributeType.ResponsePort);
		setPort(port);
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) throws MessageAttributeException {
		if ((port > 65535) || (port < 0)) {
			throw new MessageAttributeException("Port value " + port + " out of range.");
		}
		this.port = port;
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		byte[] result = new byte[8];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(4), 0, result, 2, 2);
		System.arraycopy(Utility.integerToTwoBytes(port), 0, result, 4, 2);
		result[6] = 0;
		result[7] = 0;
		return result;
	}

	public static ResponsePort parse(byte[] data) throws MessageAttributeParsingException {
		try {
			if (data.length < 2) {
				throw new MessageAttributeParsingException("Data array too short for ResponsePort");
			}
			byte[] portBytes = new byte[2];
			System.arraycopy(data, 0, portBytes, 0, 2);
			int parsedPort = Utility.twoBytesToInteger(portBytes);
			ResponsePort rp = new ResponsePort(parsedPort);
			LOGGER.debug("Message Attribute: Response Port parsed: port={}.", parsedPort);
			return rp;
		} catch (UtilityException | MessageAttributeException e) {
			throw new MessageAttributeParsingException("Parsing error");
		}
	}
}
