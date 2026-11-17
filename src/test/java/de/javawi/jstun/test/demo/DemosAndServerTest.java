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

package de.javawi.jstun.test.demo;

import static org.junit.jupiter.api.Assertions.*;

import java.net.InetAddress;

import org.junit.jupiter.api.Test;

public class DemosAndServerTest {

	@Test
	public void testDemoInstantiationsAndExecution() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");

		// DiscoveryTestDemo
		DiscoveryTestDemo demo1 = new DiscoveryTestDemo(loopback);
		assertNotNull(demo1);
		DiscoveryTestDemo demo1Port = new DiscoveryTestDemo(loopback, 54321);
		assertNotNull(demo1Port);
		// Calling run() should execute cleanly and handle any socket/DNS exceptions internally
		demo1Port.run();

		// FastDiscoveryTestDemo
		FastDiscoveryTestDemo demo2 = new FastDiscoveryTestDemo(loopback);
		assertNotNull(demo2);
		FastDiscoveryTestDemo demo2Port = new FastDiscoveryTestDemo(loopback, 54322);
		assertNotNull(demo2Port);
		demo2Port.run();

		// NatBehaviorDiscoveryTestDemo
		NatBehaviorDiscoveryTestDemo demo3 = new NatBehaviorDiscoveryTestDemo(loopback);
		assertNotNull(demo3);
		NatBehaviorDiscoveryTestDemo demo3Port = new NatBehaviorDiscoveryTestDemo(loopback, 54323);
		assertNotNull(demo3Port);
		demo3Port.run();

		// BindingLifetimeTestDemo
		BindingLifetimeTestDemo demo4 = new BindingLifetimeTestDemo();
		assertNotNull(demo4);
	}
}
