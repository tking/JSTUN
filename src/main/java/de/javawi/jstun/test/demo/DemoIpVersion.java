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

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * Shared IP version selector ({@code -4}/{@code --ipv4}, {@code -6}/{@code --ipv6})
 * for JSTUN CLI demos.
 */
public enum DemoIpVersion {
	/** Default dual-stack behavior (use both IPv4 and IPv6 as available). */
	AUTO,
	/** Restrict execution to IPv4 addresses only ({@code -4} / {@code --ipv4}). */
	IPV4,
	/** Restrict execution to IPv6 addresses only ({@code -6} / {@code --ipv6}). */
	IPV6;

	/**
	 * Result of parsing CLI arguments for optional IP version switches and remaining positional arguments.
	 */
	public static final class ParsedArgs {
		private final DemoIpVersion ipVersion;
		private final List<String> positionalArgs;

		ParsedArgs(DemoIpVersion ipVersion, List<String> positionalArgs) {
			this.ipVersion = ipVersion;
			this.positionalArgs = Collections.unmodifiableList(positionalArgs);
		}

		public DemoIpVersion getIpVersion() {
			return ipVersion;
		}

		public List<String> getPositionalArgs() {
			return positionalArgs;
		}
	}

	/**
	 * Parses {@code -4}/{@code --ipv4} and {@code -6}/{@code --ipv6} switches from CLI arguments.
	 *
	 * @throws IllegalArgumentException if both {@code -4} and {@code -6} are specified
	 *                                  or an unrecognized option flag is passed
	 */
	public static ParsedArgs parse(String[] args) {
		DemoIpVersion selected = AUTO;
		List<String> positional = new ArrayList<String>();
		if (args != null) {
			for (String arg : args) {
				if ("-4".equals(arg) || "--ipv4".equals(arg)) {
					if (selected == IPV6) {
						throw new IllegalArgumentException("Cannot specify both -4/--ipv4 and -6/--ipv6");
					}
					selected = IPV4;
				} else if ("-6".equals(arg) || "--ipv6".equals(arg)) {
					if (selected == IPV4) {
						throw new IllegalArgumentException("Cannot specify both -4/--ipv4 and -6/--ipv6");
					}
					selected = IPV6;
				} else if (arg != null && arg.startsWith("-")) {
					throw new IllegalArgumentException(
							"Unknown option '" + arg + "' (supported: -4/--ipv4, -6/--ipv6)");
				} else if (arg != null) {
					positional.add(arg);
				}
			}
		}
		return new ParsedArgs(selected, positional);
	}

	/**
	 * Returns {@code true} if {@code address} matches this IP version filter.
	 */
	public boolean matches(InetAddress address) {
		if (address == null) {
			return false;
		}
		if (this == IPV4) {
			return address instanceof Inet4Address;
		}
		if (this == IPV6) {
			return address instanceof Inet6Address;
		}
		return (address instanceof Inet4Address) || (address instanceof Inet6Address);
	}

	/**
	 * Enumerates all non-loopback, non-link-local, non-multicast local interface addresses
	 * matching this IP version filter.
	 */
	public List<InetAddress> getLocalAddresses() throws SocketException {
		List<InetAddress> result = new ArrayList<InetAddress>();
		Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
		while (ifaces != null && ifaces.hasMoreElements()) {
			NetworkInterface iface = ifaces.nextElement();
			Enumeration<InetAddress> iaddresses = iface.getInetAddresses();
			while (iaddresses.hasMoreElements()) {
				InetAddress iaddress = iaddresses.nextElement();
				if (matches(iaddress)
						&& !iaddress.isLoopbackAddress()
						&& !iaddress.isLinkLocalAddress()
						&& !iaddress.isMulticastAddress()) {
					result.add(iaddress);
				}
			}
		}
		return result;
	}

	/**
	 * Resolves {@code host} honoring this IP version filter ({@code A} for {@link #IPV4},
	 * {@code AAAA} for {@link #IPV6}, or default resolution for {@link #AUTO}).
	 */
	public InetAddress resolveHost(String host) throws UnknownHostException {
		if (this == AUTO) {
			return InetAddress.getByName(host);
		}
		InetAddress[] candidates = InetAddress.getAllByName(host);
		for (InetAddress candidate : candidates) {
			if (matches(candidate)) {
				return candidate;
			}
		}
		throw new UnknownHostException("No " + name() + " address found for host: " + host);
	}

	/**
	 * Returns the wildcard bind address matching this IP version filter and resolved target address
	 * ({@code ::} for IPv6, {@code 0.0.0.0} for IPv4).
	 */
	public InetAddress wildcardForTarget(InetAddress target) throws UnknownHostException {
		if (this == IPV6 || (this == AUTO && target instanceof Inet6Address)) {
			return InetAddress.getByName("::");
		}
		return InetAddress.getByName("0.0.0.0");
	}

	/**
	 * Returns the loopback address for self-contained demos ({@code ::1} for {@link #IPV6},
	 * {@code 127.0.0.1} otherwise).
	 */
	public InetAddress loopbackAddress() throws UnknownHostException {
		if (this == IPV6) {
			return InetAddress.getByName("::1");
		}
		return InetAddress.getByName("127.0.0.1");
	}
}
