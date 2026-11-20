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

package de.javawi.jstun;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

import de.javawi.jstun.attribute.ExceptionsAndEdgeCasesTest;
import de.javawi.jstun.attribute.MappedAddressTest;
import de.javawi.jstun.attribute.Rfc5389And8489Test;
import de.javawi.jstun.attribute.Rfc5769TestVectorsTest;
import de.javawi.jstun.attribute.StunAttributesAndUtilityTest;
import de.javawi.jstun.header.MessageHeaderTest;
import de.javawi.jstun.test.BindingLifetimeAndStunServerTest;
import de.javawi.jstun.test.DiscoveryInfoTest;
import de.javawi.jstun.test.Rfc3489DiscoveryAlgorithmTest;
import de.javawi.jstun.test.Rfc5780AttributesAndDiscoveryTest;
import de.javawi.jstun.test.StunSocketReceiverTest;
import de.javawi.jstun.test.demo.DemosAndServerTest;
import de.javawi.jstun.test.demo.ice.ICENegotiatorTest;
import de.javawi.jstun.turn.Rfc5766TurnClientServerTest;
import de.javawi.jstun.turn.Rfc5766WireProtocolTest;
import de.javawi.jstun.util.AddressTest;

@Suite
@SelectClasses({
	AddressTest.class,
	MappedAddressTest.class,
	MessageHeaderTest.class,
	Rfc5389And8489Test.class,
	Rfc5769TestVectorsTest.class,
	StunAttributesAndUtilityTest.class,
	ExceptionsAndEdgeCasesTest.class,
	DiscoveryInfoTest.class,
	Rfc3489DiscoveryAlgorithmTest.class,
	Rfc5780AttributesAndDiscoveryTest.class,
	BindingLifetimeAndStunServerTest.class,
	StunSocketReceiverTest.class,
	Rfc5766WireProtocolTest.class,
	Rfc5766TurnClientServerTest.class,
	ICENegotiatorTest.class,
	DemosAndServerTest.class
})
public class AllTests {

}
