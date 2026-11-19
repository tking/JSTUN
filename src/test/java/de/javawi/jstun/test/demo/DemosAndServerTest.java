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
import java.nio.file.Path;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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

		// MtuDiscoveryTestDemo
		MtuDiscoveryTestDemo demoMtu = new MtuDiscoveryTestDemo(loopback);
		assertNotNull(demoMtu);
		MtuDiscoveryTestDemo demoMtuPort = new MtuDiscoveryTestDemo(loopback, 54324);
		assertNotNull(demoMtuPort);
		demoMtuPort.run();

		// HairpinningDiscoveryTestDemo
		HairpinningDiscoveryTestDemo demoHairpin = new HairpinningDiscoveryTestDemo(loopback);
		assertNotNull(demoHairpin);
		HairpinningDiscoveryTestDemo demoHairpinPort = new HairpinningDiscoveryTestDemo(loopback, 54325);
		assertNotNull(demoHairpinPort);
		demoHairpinPort.run();

		// BindingLifetimeTestDemo
		BindingLifetimeTestDemo demo4 = new BindingLifetimeTestDemo();
		assertNotNull(demo4);
	}

	@Test
	public void testStunServerRotatingLogFileHandler(@TempDir Path tempDir) throws Exception {
		assertTrue(StunServer.LOG_FILE_LIMIT_BYTES > 0);
		assertTrue(StunServer.LOG_FILE_COUNT > 1);
		assertTrue(StunServer.LOG_FILE_PATTERN.contains("%g"));

		String pattern = tempDir.resolve("logging_server.%g.txt").toString();
		FileHandler handler = StunServer.createLogFileHandler(pattern);
		try {
			assertNotNull(handler);
			assertInstanceOf(SimpleFormatter.class, handler.getFormatter());
			assertEquals(Level.INFO, handler.getLevel());
		} finally {
			handler.close();
		}

		// Configurable log level via -Djstun.log.level
		assertEquals(Level.INFO, StunServer.resolveLogLevel(null));
		assertEquals(Level.INFO, StunServer.resolveLogLevel(""));
		assertEquals(Level.INFO, StunServer.resolveLogLevel("INVALID_LEVEL"));
		assertEquals(Level.ALL, StunServer.resolveLogLevel("ALL"));
		assertEquals(Level.FINE, StunServer.resolveLogLevel("fine"));

		Logger testLogger = Logger.getLogger("de.javawi.jstun.test.logconfig");
		Logger rootLogger = Logger.getLogger("");
		java.util.logging.Handler[] rootHandlers = rootLogger.getHandlers();
		Level[] savedRootLevels = new Level[rootHandlers.length];
		for (int i = 0; i < rootHandlers.length; i++) {
			savedRootLevels[i] = rootHandlers[i].getLevel();
		}
		FileHandler allHandler = StunServer.createLogFileHandler(tempDir.resolve("logging_all.%g.txt").toString(), Level.ALL);
		try {
			Level applied = StunServer.configureLogging(testLogger, allHandler, "ALL");
			assertEquals(Level.ALL, applied);
			assertEquals(Level.ALL, testLogger.getLevel());
			assertEquals(Level.ALL, allHandler.getLevel());
		} finally {
			testLogger.removeHandler(allHandler);
			allHandler.close();
			for (int i = 0; i < rootHandlers.length; i++) {
				rootHandlers[i].setLevel(savedRootLevels[i]);
			}
		}
	}
}
