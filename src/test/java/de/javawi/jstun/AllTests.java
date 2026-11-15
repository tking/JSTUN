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

import de.javawi.jstun.attribute.MappedAddressTest;
import de.javawi.jstun.attribute.Rfc5769TestVectorsTest;
import de.javawi.jstun.header.MessageHeaderTest;
import de.javawi.jstun.test.Rfc5780AttributesAndDiscoveryTest;
import de.javawi.jstun.util.AddressTest;

@Suite
@SelectClasses({ AddressTest.class, MappedAddressTest.class, MessageHeaderTest.class, Rfc5769TestVectorsTest.class,
		Rfc5780AttributesAndDiscoveryTest.class })
public class AllTests {

}
