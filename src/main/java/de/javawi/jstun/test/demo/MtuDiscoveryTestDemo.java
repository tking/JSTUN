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

import java.net.BindException;
import java.net.InetAddress;
import java.util.List;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.SimpleFormatter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.test.MtuDiscoveryTest;

public class MtuDiscoveryTestDemo implements Runnable {
	private static final Logger LOGGER = LoggerFactory.getLogger(MtuDiscoveryTestDemo.class);
	InetAddress iaddress;
	int port;

	public MtuDiscoveryTestDemo(InetAddress iaddress, int port) {
		this.iaddress = iaddress;
		this.port = port;
	}

	public MtuDiscoveryTestDemo(InetAddress iaddress) {
		this.iaddress = iaddress;
		this.port = 0;
	}

	public void run() {
		try {
			MtuDiscoveryTest test = new MtuDiscoveryTest(iaddress, port, "jstun.t-king.de", 3478);
			int discoveredMtu = test.test();
			LOGGER.info("MtuDiscoveryTest result for {}: discoveredMtu={} bytes", iaddress, discoveredMtu);
			System.out.println("Local IP: " + iaddress.getHostAddress() + " -> Discovered Path MTU: " + discoveredMtu + " bytes");
		} catch (BindException be) {
			LOGGER.warn("Unable to bind {}: {}", iaddress, be.getMessage());
			System.out.println(iaddress.toString() + ": " + be.getMessage());
		} catch (Exception e) {
			LOGGER.error("Error running MtuDiscoveryTestDemo on {}: {}", iaddress, e.getMessage(), e);
			System.out.println(e.getMessage());
		}
	}

	public static void main(String args[]) {
		try {
			DemoIpVersion.ParsedArgs parsed = DemoIpVersion.parse(args);
			if (!parsed.getPositionalArgs().isEmpty()) {
				System.err.println("usage: java de.javawi.jstun.test.demo.MtuDiscoveryTestDemo [-4|--ipv4 | -6|--ipv6]");
				return;
			}
			Handler fh = new FileHandler("logging.txt");
			fh.setFormatter(new SimpleFormatter());
			java.util.logging.Logger.getLogger("de.javawi.jstun").addHandler(fh);
			java.util.logging.Logger.getLogger("de.javawi.jstun").setLevel(Level.ALL);

			List<InetAddress> addresses = parsed.getIpVersion().getLocalAddresses();
			if (addresses.isEmpty()) {
				System.out.println("No suitable " + parsed.getIpVersion() + " network interface addresses found.");
				return;
			}
			for (InetAddress iaddress : addresses) {
				Thread thread = new Thread(new MtuDiscoveryTestDemo(iaddress));
				thread.start();
			}
		} catch (IllegalArgumentException iae) {
			System.err.println("Error: " + iae.getMessage());
			System.err.println("usage: java de.javawi.jstun.test.demo.MtuDiscoveryTestDemo [-4|--ipv4 | -6|--ipv6]");
		} catch (Exception e) {
			LOGGER.error("Error initializing MtuDiscoveryTestDemo: {}", e.getMessage(), e);
			System.out.println(e.getMessage());
		}
	}
}
