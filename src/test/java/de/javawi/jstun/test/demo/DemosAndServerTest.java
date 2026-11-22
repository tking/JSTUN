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

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.util.List;
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

		// Configurable stats interval
		assertEquals(StunServer.DEFAULT_STATS_INTERVAL_SECONDS, StunServer.resolveStatsIntervalSeconds(null));
		assertEquals(StunServer.DEFAULT_STATS_INTERVAL_SECONDS, StunServer.resolveStatsIntervalSeconds(""));
		assertEquals(StunServer.DEFAULT_STATS_INTERVAL_SECONDS, StunServer.resolveStatsIntervalSeconds("not-a-number"));
		assertEquals(0L, StunServer.resolveStatsIntervalSeconds("0"));
		assertEquals(30L, StunServer.resolveStatsIntervalSeconds("30"));

		// Named receiver threads
		InetAddress loopback = InetAddress.getByName("127.0.0.1");
		int[] ports = new int[4];
		java.net.DatagramSocket[] tempSockets = new java.net.DatagramSocket[4];
		for (int i = 0; i < 4; i++) {
			tempSockets[i] = new java.net.DatagramSocket(0, loopback);
			ports[i] = tempSockets[i].getLocalPort();
		}
		for (java.net.DatagramSocket s : tempSockets) {
			s.close();
		}
		StunServer server = new StunServer(ports[0], loopback, ports[1], loopback, ports[2], ports[3]);
		server.setStatsIntervalSeconds(1);
		server.start();
		try {
			assertEquals(4, server.getReceiverThreads().size());
			for (StunServer.StunServerReceiverThread t : server.getReceiverThreads()) {
				assertTrue(t.getName().startsWith("stun-recv-127.0.0.1:"), "Unexpected thread name: " + t.getName());
			}
		} finally {
			server.stop();
		}

		// Address-family mismatch and null validation in StunServer constructors
		InetAddress ipv6Loopback = InetAddress.getByName("::1");
		assertThrows(IllegalArgumentException.class, () -> new StunServer(0, loopback, 0, ipv6Loopback));
		assertThrows(IllegalArgumentException.class, () -> new StunServer(0, null, 0, loopback));
		assertThrows(IllegalArgumentException.class, () -> new StunServer(0, null, 0, null, null, null));
		assertThrows(IllegalArgumentException.class, () -> new StunServer(0, loopback, 0, null, null, null));
		assertThrows(IllegalArgumentException.class, () -> new StunServer(0, null, 0, null, ipv6Loopback, null));
		assertThrows(IllegalArgumentException.class, () -> new StunServer(0, ipv6Loopback, 0, ipv6Loopback, null, null));
		assertThrows(IllegalArgumentException.class, () -> new StunServer(0, null, 0, null, loopback, loopback));

		// Optional-family IPv4-only constructor
		StunServer v4Only = new StunServer(0, loopback, 0, loopback, null, null);
		assertTrue(v4Only.isIpv4Enabled());
		assertFalse(v4Only.isIpv6Enabled());
		v4Only.start();
		try {
			assertEquals(4, v4Only.getReceiverThreads().size());
		} finally {
			v4Only.stop();
		}

		// CLI argument parsing: 4 args (IPv4-only), 6 args & 8 args (dual-stack in either order), and invalid args
		assertThrows(IllegalArgumentException.class, () -> StunServer.createFromArgs(new String[] { "3478", "127.0.0.1" }));
		assertThrows(IllegalArgumentException.class,
				() -> StunServer.createFromArgs(new String[] { "0", "127.0.0.1", "0", "127.0.0.1", "127.0.0.1", "127.0.0.1" }));
		StunServer cliV4 = StunServer.createFromArgs(new String[] { "0", "127.0.0.1", "0", "127.0.0.1" });
		assertTrue(cliV4.isIpv4Enabled());
		assertFalse(cliV4.isIpv6Enabled());
		cliV4.stop();

		boolean ipv6Available = false;
		try (java.net.DatagramSocket probe = new java.net.DatagramSocket(0, ipv6Loopback)) {
			ipv6Available = probe.getLocalPort() > 0;
		} catch (Exception ignored) {
		}
		if (ipv6Available) {
			StunServer cliDual6 = StunServer.createFromArgs(
					new String[] { "0", "127.0.0.1", "0", "127.0.0.1", "::1", "::1" });
			assertTrue(cliDual6.isIpv4Enabled());
			assertTrue(cliDual6.isIpv6Enabled());
			cliDual6.setStatsIntervalSeconds(0);
			cliDual6.start();
			try {
				assertEquals(8, cliDual6.getReceiverThreads().size());
			} finally {
				cliDual6.stop();
			}

			StunServer cliDual8Reversed = StunServer.createFromArgs(
					new String[] { "0", "::1", "0", "::1", "0", "127.0.0.1", "0", "127.0.0.1" });
			assertTrue(cliDual8Reversed.isIpv4Enabled());
			assertTrue(cliDual8Reversed.isIpv6Enabled());
			cliDual8Reversed.stop();
		}

		// RFC 5952 IPv6 endpoint bracket formatting
		assertEquals("127.0.0.1:3478", StunServer.formatEndpoint(loopback, 3478));
		String v6Formatted = StunServer.formatEndpoint(ipv6Loopback, 3478);
		assertTrue(v6Formatted.startsWith("[") && v6Formatted.endsWith("]:3478"),
				"Expected bracketed IPv6 endpoint, got: " + v6Formatted);
	}

	@Test
	public void testDemoIpVersionSwitchParsingResolutionAndFiltering() throws Exception {
		// Default (no args / null) -> AUTO
		DemoIpVersion.ParsedArgs def = DemoIpVersion.parse(null);
		assertEquals(DemoIpVersion.AUTO, def.getIpVersion());
		assertTrue(def.getPositionalArgs().isEmpty());

		DemoIpVersion.ParsedArgs empty = DemoIpVersion.parse(new String[0]);
		assertEquals(DemoIpVersion.AUTO, empty.getIpVersion());

		// -4 / --ipv4 and -6 / --ipv6 switches with positional args
		DemoIpVersion.ParsedArgs v4 = DemoIpVersion.parse(new String[] { "-4", "host", "3478" });
		assertEquals(DemoIpVersion.IPV4, v4.getIpVersion());
		assertEquals(List.of("host", "3478"), v4.getPositionalArgs());

		DemoIpVersion.ParsedArgs v4Long = DemoIpVersion.parse(new String[] { "host", "--ipv4" });
		assertEquals(DemoIpVersion.IPV4, v4Long.getIpVersion());
		assertEquals(List.of("host"), v4Long.getPositionalArgs());

		DemoIpVersion.ParsedArgs v6 = DemoIpVersion.parse(new String[] { "-6" });
		assertEquals(DemoIpVersion.IPV6, v6.getIpVersion());
		assertTrue(v6.getPositionalArgs().isEmpty());

		DemoIpVersion.ParsedArgs v6Long = DemoIpVersion.parse(new String[] { "--ipv6", "peer", "3478" });
		assertEquals(DemoIpVersion.IPV6, v6Long.getIpVersion());
		assertEquals(List.of("peer", "3478"), v6Long.getPositionalArgs());

		// Conflicting or unknown flags throw IllegalArgumentException
		assertThrows(IllegalArgumentException.class, () -> DemoIpVersion.parse(new String[] { "-4", "-6" }));
		assertThrows(IllegalArgumentException.class, () -> DemoIpVersion.parse(new String[] { "--ipv6", "--ipv4" }));
		assertThrows(IllegalArgumentException.class, () -> DemoIpVersion.parse(new String[] { "--bogus" }));

		// Family matching, host resolution, wildcard, and loopback helpers
		InetAddress v4Addr = InetAddress.getByName("127.0.0.1");
		InetAddress v6Addr = InetAddress.getByName("::1");
		assertTrue(DemoIpVersion.AUTO.matches(v4Addr));
		assertTrue(DemoIpVersion.AUTO.matches(v6Addr));
		assertFalse(DemoIpVersion.AUTO.matches(null));
		assertTrue(DemoIpVersion.IPV4.matches(v4Addr));
		assertFalse(DemoIpVersion.IPV4.matches(v6Addr));
		assertFalse(DemoIpVersion.IPV6.matches(v4Addr));
		assertTrue(DemoIpVersion.IPV6.matches(v6Addr));

		assertTrue(DemoIpVersion.IPV4.resolveHost("127.0.0.1") instanceof Inet4Address);
		assertTrue(DemoIpVersion.IPV6.resolveHost("::1") instanceof Inet6Address);
		assertTrue(DemoIpVersion.AUTO.resolveHost("127.0.0.1") instanceof Inet4Address);
		assertThrows(UnknownHostException.class, () -> DemoIpVersion.IPV6.resolveHost("127.0.0.1"));
		assertThrows(UnknownHostException.class, () -> DemoIpVersion.IPV4.resolveHost("::1"));

		assertTrue(DemoIpVersion.IPV4.wildcardForTarget(v4Addr) instanceof Inet4Address);
		assertTrue(DemoIpVersion.IPV6.wildcardForTarget(v6Addr) instanceof Inet6Address);
		assertTrue(DemoIpVersion.AUTO.wildcardForTarget(v6Addr) instanceof Inet6Address);
		assertTrue(DemoIpVersion.AUTO.wildcardForTarget(v4Addr) instanceof Inet4Address);

		assertEquals(v4Addr, DemoIpVersion.AUTO.loopbackAddress());
		assertEquals(v4Addr, DemoIpVersion.IPV4.loopbackAddress());
		assertEquals(v6Addr, DemoIpVersion.IPV6.loopbackAddress());

		// Local address enumeration filters match family
		for (InetAddress addr : DemoIpVersion.IPV4.getLocalAddresses()) {
			assertTrue(addr instanceof Inet4Address);
		}
		for (InetAddress addr : DemoIpVersion.IPV6.getLocalAddresses()) {
			assertTrue(addr instanceof Inet6Address);
		}

		// Demo CLI invalid-flag handling returns cleanly without exiting the JVM
		DiscoveryTestDemo.main(new String[] { "-4", "-6" });
		FastDiscoveryTestDemo.main(new String[] { "--unknown" });
		NatBehaviorDiscoveryTestDemo.main(new String[] { "unexpected-arg" });
		MtuDiscoveryTestDemo.main(new String[] { "--unknown" });
		HairpinningDiscoveryTestDemo.main(new String[] { "-4", "-6" });
		BindingLifetimeTestDemo.main(new String[] { "--unknown" });
		TurnClientDemo.main(new String[] { "-4", "-6" });
		TurnClientDemo.main(new String[] { "-4" });
		ConsentFreshnessDemo.main(new String[] { "-4", "-6" });
		ConsentFreshnessDemo.main(new String[] { "only-one-arg" });

		// ConsentFreshnessDemo loopback over IPv4 (-4) and IPv6 (-6 if ::1 is available)
		ConsentFreshnessDemo.main(new String[] { "-4" });
		boolean ipv6Available = false;
		try (java.net.DatagramSocket probe = new java.net.DatagramSocket(0, v6Addr)) {
			ipv6Available = probe.getLocalPort() > 0;
		} catch (Exception ignored) {
		}
		if (ipv6Available) {
			ConsentFreshnessDemo.main(new String[] { "-6" });
		}
	}
}
