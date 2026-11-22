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

import java.net.InetAddress;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.SimpleFormatter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.test.BindingLifetimeTest;

public class BindingLifetimeTestDemo {
	private static final Logger LOGGER = LoggerFactory.getLogger(BindingLifetimeTestDemo.class);

	public static void main(String args[]) {
		try {
			DemoIpVersion.ParsedArgs parsed = DemoIpVersion.parse(args);
			if (!parsed.getPositionalArgs().isEmpty()) {
				System.err.println("usage: java de.javawi.jstun.test.demo.BindingLifetimeTestDemo [-4|--ipv4 | -6|--ipv6]");
				return;
			}
			Handler fh = new FileHandler("logging.txt");
			fh.setFormatter(new SimpleFormatter());
			java.util.logging.Logger.getLogger("de.javawi.jstun").addHandler(fh);
			java.util.logging.Logger.getLogger("de.javawi.jstun").setLevel(Level.ALL);
			InetAddress serverAddr = parsed.getIpVersion().resolveHost("jstun.t-king.de");
			BindingLifetimeTest test = new BindingLifetimeTest(serverAddr.getHostAddress(), 3478);
			// iphone-stun.freenet.de:3478
			// larry.gloo.net:3478
			// stun.xten.net:3478
			test.test();
			boolean continueWhile = true;
			while(continueWhile) {
				Thread.sleep(5000);
				if (test.getLifetime() != -1) {
					LOGGER.info("Lifetime: {} Finished: {}", test.getLifetime(), test.isCompleted());
					System.out.println("Lifetime: " + test.getLifetime() + " Finished: " + test.isCompleted());
					if (test.isCompleted()) continueWhile = false;
				}
			}
		} catch (IllegalArgumentException iae) {
			System.err.println("Error: " + iae.getMessage());
			System.err.println("usage: java de.javawi.jstun.test.demo.BindingLifetimeTestDemo [-4|--ipv4 | -6|--ipv6]");
		} catch (Exception e) {
			LOGGER.error("Error running BindingLifetimeTestDemo: {}", e.getMessage(), e);
			System.out.println(e.getMessage());
		}
	}
}
