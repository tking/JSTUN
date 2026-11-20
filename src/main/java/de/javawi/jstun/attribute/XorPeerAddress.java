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
 * XOR-PEER-ADDRESS attribute ({@code 0x0012}) as defined in RFC 5766 §14.3.
 * <p>
 * Uses the exact same IPv4/IPv6 XOR encoding as {@link XorMappedAddress}.
 */
public class XorPeerAddress extends XorMappedAddress {
	private static final Logger LOGGER = LoggerFactory.getLogger(XorPeerAddress.class);

	public XorPeerAddress() {
		super(MessageAttributeType.XorPeerAddress);
	}

	public XorPeerAddress(byte[] transactionId) {
		super(MessageAttributeType.XorPeerAddress, transactionId);
	}

	public static XorPeerAddress parse(byte[] data) throws MessageAttributeParsingException {
		return parse(data, null);
	}

	public static XorPeerAddress parse(byte[] data, byte[] transactionId) throws MessageAttributeParsingException {
		XorPeerAddress xpa = new XorPeerAddress(transactionId);
		parseInto(xpa, data, transactionId);
		LOGGER.debug("Message Attribute: XOR-Peer Address parsed: {}.", xpa);
		return xpa;
	}
}
