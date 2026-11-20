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
 * REQUESTED-TRANSPORT attribute ({@code 0x0019}) as defined in RFC 5766 §14.7.
 * <p>
 * 1-byte IANA transport protocol number ({@code 17} = UDP) followed by 3 zero RFFU bytes.
 */
public class RequestedTransport extends MessageAttribute {
	private static final Logger LOGGER = LoggerFactory.getLogger(RequestedTransport.class);
	public static final int PROTOCOL_UDP = 17;
	public static final int PROTOCOL_TCP = 6;

	private int protocol = PROTOCOL_UDP;

	public RequestedTransport() {
		super(MessageAttributeType.RequestedTransport);
	}

	public RequestedTransport(int protocol) throws MessageAttributeException {
		super(MessageAttributeType.RequestedTransport);
		setProtocol(protocol);
	}

	public int getProtocol() {
		return protocol;
	}

	public void setProtocol(int protocol) throws MessageAttributeException {
		if (protocol < 0 || protocol > 255) {
			throw new MessageAttributeException("Transport protocol out of range (0..255): " + protocol);
		}
		this.protocol = protocol;
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		byte[] result = new byte[8];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(4), 0, result, 2, 2);
		result[4] = Utility.integerToOneByte(protocol);
		// bytes 5..7 are RFFU (zero)
		return result;
	}

	public static RequestedTransport parse(byte[] data) throws MessageAttributeParsingException {
		try {
			if (data == null || data.length != 4) {
				throw new MessageAttributeParsingException("Invalid length for REQUESTED-TRANSPORT");
			}
			int proto = Utility.oneByteToInteger(data[0]);
			LOGGER.debug("Message Attribute: RequestedTransport parsed: protocol={}.", proto);
			return new RequestedTransport(proto);
		} catch (UtilityException | MessageAttributeException e) {
			throw new MessageAttributeParsingException("Invalid REQUESTED-TRANSPORT: " + e.getMessage());
		}
	}
}
