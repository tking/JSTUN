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

/**
 * XOR-RELAYED-ADDRESS attribute ({@code 0x0016}) as defined in RFC 5766 §14.5.
 * <p>
 * Uses the exact same IPv4/IPv6 XOR encoding as {@link XorMappedAddress}.
 */
public class XorRelayedAddress extends XorMappedAddress {
	private static final Logger LOGGER = LoggerFactory.getLogger(XorRelayedAddress.class);

	public XorRelayedAddress() {
		super(MessageAttributeType.XorRelayedAddress);
	}

	public XorRelayedAddress(byte[] transactionId) {
		super(MessageAttributeType.XorRelayedAddress, transactionId);
	}

	public static XorRelayedAddress parse(byte[] data) throws MessageAttributeParsingException {
		return parse(data, null);
	}

	public static XorRelayedAddress parse(byte[] data, byte[] transactionId) throws MessageAttributeParsingException {
		XorRelayedAddress xra = new XorRelayedAddress(transactionId);
		parseInto(xra, data, transactionId);
		LOGGER.debug("Message Attribute: XOR-Relayed Address parsed: {}.", xra);
		return xra;
	}
}
