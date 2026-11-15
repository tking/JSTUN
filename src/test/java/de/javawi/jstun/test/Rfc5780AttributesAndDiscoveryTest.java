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

package de.javawi.jstun.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.attribute.OtherAddress;
import de.javawi.jstun.attribute.Padding;
import de.javawi.jstun.attribute.ResponseOrigin;
import de.javawi.jstun.attribute.ResponsePort;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.test.DiscoveryInfo.FilteringBehavior;
import de.javawi.jstun.test.DiscoveryInfo.MappingBehavior;
import de.javawi.jstun.util.Address;

public class Rfc5780AttributesAndDiscoveryTest {

	@Test
	public void testOtherAddressAndResponseOriginRoundTrip() throws Exception {
		MessageHeader mh = new MessageHeader(MessageHeaderType.BindingResponse);
		mh.generateTransactionID();

		OtherAddress oa = new OtherAddress();
		oa.setAddress(new Address("198.51.100.2"));
		oa.setPort(3479);
		mh.addMessageAttribute(oa);

		ResponseOrigin ro = new ResponseOrigin();
		ro.setAddress(new Address("198.51.100.1"));
		ro.setPort(3478);
		mh.addMessageAttribute(ro);

		byte[] bytes = mh.getBytes();
		MessageHeader parsed = MessageHeader.parseHeader(bytes);
		parsed.parseAttributes(bytes);

		OtherAddress parsedOa = (OtherAddress) parsed.getMessageAttribute(MessageAttributeType.OtherAddress);
		assertNotNull(parsedOa);
		assertEquals(new Address("198.51.100.2"), parsedOa.getAddress());
		assertEquals(3479, parsedOa.getPort());

		ResponseOrigin parsedRo = (ResponseOrigin) parsed.getMessageAttribute(MessageAttributeType.ResponseOrigin);
		assertNotNull(parsedRo);
		assertEquals(new Address("198.51.100.1"), parsedRo.getAddress());
		assertEquals(3478, parsedRo.getPort());
	}

	@Test
	public void testResponsePortAndPaddingRoundTrip() throws Exception {
		MessageHeader mh = new MessageHeader(MessageHeaderType.BindingRequest);
		mh.generateTransactionID();

		ResponsePort rp = new ResponsePort(45678);
		mh.addMessageAttribute(rp);

		Padding pad = new Padding(10); // padded to 12 bytes
		mh.addMessageAttribute(pad);

		byte[] bytes = mh.getBytes();
		MessageHeader parsed = MessageHeader.parseHeader(bytes);
		parsed.parseAttributes(bytes);

		ResponsePort parsedRp = (ResponsePort) parsed.getMessageAttribute(MessageAttributeType.ResponsePort);
		assertNotNull(parsedRp);
		assertEquals(45678, parsedRp.getPort());

		Padding parsedPad = (Padding) parsed.getMessageAttribute(MessageAttributeType.Padding);
		assertNotNull(parsedPad);
		assertEquals(12, parsedPad.getPaddingLength());
	}

	@Test
	public void testDiscoveryInfoRfc5780Behaviors() throws Exception {
		DiscoveryInfo di = new DiscoveryInfo(InetAddress.getByName("127.0.0.1"));
		assertEquals(MappingBehavior.UNKNOWN, di.getMappingBehavior());
		assertEquals(FilteringBehavior.UNKNOWN, di.getFilteringBehavior());

		di.setMappingBehavior(MappingBehavior.ENDPOINT_INDEPENDENT);
		di.setFilteringBehavior(FilteringBehavior.ADDRESS_AND_PORT_DEPENDENT);
		di.setPortRestrictedCone();
		di.setPublicIP(InetAddress.getByName("203.0.113.10"));
		di.setPublicPort(50000);

		assertEquals(MappingBehavior.ENDPOINT_INDEPENDENT, di.getMappingBehavior());
		assertEquals(FilteringBehavior.ADDRESS_AND_PORT_DEPENDENT, di.getFilteringBehavior());
		String summary = di.toString();
		assertTrue(summary.contains("ENDPOINT_INDEPENDENT"));
		assertTrue(summary.contains("ADDRESS_AND_PORT_DEPENDENT"));
	}
}
