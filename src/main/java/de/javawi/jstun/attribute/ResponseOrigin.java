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

public class ResponseOrigin extends MappedResponseChangedSourceAddressReflectedFrom {
	private static final Logger LOGGER = LoggerFactory.getLogger(ResponseOrigin.class);

	public ResponseOrigin() {
		super(MessageAttribute.MessageAttributeType.ResponseOrigin);
	}

	public static MessageAttribute parse(byte[] data) throws MessageAttributeParsingException {
		ResponseOrigin ro = new ResponseOrigin();
		MappedResponseChangedSourceAddressReflectedFrom.parse(ro, data);
		LOGGER.debug("Message Attribute: Response Origin parsed: " + ro.toString() + ".");
		return ro;
	}
}
