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
import java.net.InetSocketAddress;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.turn.TurnClient;

/**
 * CLI demo for RFC 5766 (TURN) relay allocation, refresh, and clean deallocation.
 */
public class TurnClientDemo implements Runnable {
	private static final Logger LOGGER = LoggerFactory.getLogger(TurnClientDemo.class);
	private final InetAddress localAddress;
	private final String turnServer;
	private final int turnPort;
	private final String username;
	private final String password;

	public TurnClientDemo(InetAddress localAddress, String turnServer, int turnPort, String username, String password) {
		this.localAddress = localAddress;
		this.turnServer = turnServer;
		this.turnPort = turnPort;
		this.username = username;
		this.password = password;
	}

	@Override
	public void run() {
		try (TurnClient client = new TurnClient(localAddress, turnServer, turnPort, username, password)) {
			InetSocketAddress relayed = client.allocate();
			LOGGER.info("TURN relay allocated: relayed={}, mapped={}, lifetime={}s",
					relayed, client.getMappedAddress(), client.getLifetimeSeconds());
			System.out.println("TURN Relay Address: " + relayed);
			System.out.println("Mapped Address:     " + client.getMappedAddress());
			System.out.println("Lifetime:           " + client.getLifetimeSeconds() + "s");
		} catch (Exception e) {
			LOGGER.error("Error running TurnClientDemo against {}:{}: {}", turnServer, turnPort, e.getMessage(), e);
			System.out.println("TURN allocation failed: " + e.getMessage());
		}
	}

	public static void main(String[] args) {
		try {
			DemoIpVersion.ParsedArgs parsed = DemoIpVersion.parse(args);
			List<String> pos = parsed.getPositionalArgs();
			if (pos.size() != 4) {
				System.out.println("usage: java de.javawi.jstun.test.demo.TurnClientDemo [-4|--ipv4 | -6|--ipv6] SERVER PORT USERNAME PASSWORD");
				return;
			}
			DemoIpVersion ipVersion = parsed.getIpVersion();
			InetAddress target = ipVersion.resolveHost(pos.get(0));
			InetAddress wildcard = ipVersion.wildcardForTarget(target);
			new TurnClientDemo(wildcard, target.getHostAddress(), Integer.parseInt(pos.get(1)), pos.get(2), pos.get(3)).run();
		} catch (IllegalArgumentException iae) {
			System.err.println("Error: " + iae.getMessage());
			System.err.println("usage: java de.javawi.jstun.test.demo.TurnClientDemo [-4|--ipv4 | -6|--ipv6] SERVER PORT USERNAME PASSWORD");
		} catch (Exception e) {
			LOGGER.error("Error initializing TurnClientDemo: {}", e.getMessage(), e);
			System.out.println(e.getMessage());
		}
	}
}
