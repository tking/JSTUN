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
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;
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
			Handler fh = new FileHandler("logging.txt");
			fh.setFormatter(new SimpleFormatter());
			java.util.logging.Logger.getLogger("de.javawi.jstun").addHandler(fh);
			java.util.logging.Logger.getLogger("de.javawi.jstun").setLevel(Level.ALL);

			Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
			while (ifaces.hasMoreElements()) {
				NetworkInterface iface = ifaces.nextElement();
				Enumeration<InetAddress> iaddresses = iface.getInetAddresses();
				while (iaddresses.hasMoreElements()) {
					InetAddress iaddress = iaddresses.nextElement();
					if (iaddress instanceof Inet4Address) {
						if ((!iaddress.isLoopbackAddress()) && (!iaddress.isLinkLocalAddress())) {
							Thread thread = new Thread(new MtuDiscoveryTestDemo(iaddress));
							thread.start();
						}
					}
				}
			}
		} catch (Exception e) {
			LOGGER.error("Error initializing MtuDiscoveryTestDemo: {}", e.getMessage(), e);
			System.out.println(e.getMessage());
		}
	}
}
