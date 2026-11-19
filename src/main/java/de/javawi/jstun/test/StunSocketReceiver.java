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

package de.javawi.jstun.test;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.attribute.Fingerprint;
import de.javawi.jstun.attribute.MessageAttribute;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.util.UtilityException;

/**
 * Shared client-side UDP receive helper that enforces an absolute wall-clock
 * deadline, slices datagrams to {@link DatagramPacket#getLength()}, discards
 * malformed or non-STUN packets, verifies {@code FINGERPRINT} when present,
 * and matches the expected STUN transaction ID.
 */
final class StunSocketReceiver {
	private static final Logger LOGGER = LoggerFactory.getLogger(StunSocketReceiver.class);
	static final int DEFAULT_BUFFER_SIZE = 512;

	private StunSocketReceiver() {
	}

	/**
	 * Resolves {@code host} to an {@link InetAddress} matching the IP address family
	 * (IPv4 or IPv6) of {@code sourceAddress}. When {@code sourceAddress} is {@code null}
	 * or a wildcard address ({@code 0.0.0.0} / {@code ::}), returns the first resolved address.
	 */
	static InetAddress resolveServerAddress(String host, InetAddress sourceAddress) throws UnknownHostException {
		InetAddress[] candidates = InetAddress.getAllByName(host);
		if (sourceAddress == null || sourceAddress.isAnyLocalAddress()) {
			return candidates[0];
		}
		boolean wantV6 = sourceAddress instanceof Inet6Address;
		for (InetAddress candidate : candidates) {
			if (wantV6 == (candidate instanceof Inet6Address)) {
				return candidate;
			}
		}
		throw new UnknownHostException("No " + (wantV6 ? "IPv6" : "IPv4")
				+ " address found for STUN server host: " + host);
	}

	static MessageHeader receiveMatching(DatagramSocket socket, MessageHeader expectedRequest, int timeoutMs)
			throws IOException {
		return receiveMatching(socket, expectedRequest, timeoutMs, DEFAULT_BUFFER_SIZE);
	}

	static MessageHeader receiveMatching(DatagramSocket socket, MessageHeader expectedRequest, int timeoutMs,
			int bufferSize) throws IOException {
		long effectiveTimeoutMs = Math.max(1L, timeoutMs);
		long deadlineNanos = System.nanoTime() + effectiveTimeoutMs * 1_000_000L;
		byte[] buf = new byte[Math.max(20, bufferSize)];

		while (true) {
			long remainingNanos = deadlineNanos - System.nanoTime();
			if (remainingNanos <= 0L) {
				throw new SocketTimeoutException("Timed out waiting for matching STUN response");
			}
			int remainingMs = (int) Math.max(1L, Math.min(Integer.MAX_VALUE, (remainingNanos + 999_999L) / 1_000_000L));
			socket.setSoTimeout(remainingMs);

			DatagramPacket receive = new DatagramPacket(buf, buf.length);
			socket.receive(receive);

			byte[] packetData = Arrays.copyOf(receive.getData(), receive.getLength());
			MessageHeader receiveMH;
			try {
				receiveMH = MessageHeader.parseHeader(packetData);
				receiveMH.parseAttributes(packetData);
			} catch (MessageHeaderParsingException | MessageAttributeParsingException | RuntimeException e) {
				LOGGER.debug("Discarding malformed/non-STUN UDP packet ({} bytes) from {}:{}: {}",
						packetData.length, receive.getAddress().getHostAddress(), receive.getPort(), e.getMessage());
				continue;
			}

			if (receiveMH.getMessageAttribute(MessageAttribute.MessageAttributeType.Fingerprint) != null) {
				try {
					if (!Fingerprint.verify(packetData)) {
						LOGGER.warn("Discarding STUN packet with invalid FINGERPRINT from {}:{}.",
								receive.getAddress().getHostAddress(), receive.getPort());
						continue;
					}
				} catch (UtilityException | MessageAttributeParsingException | RuntimeException e) {
					LOGGER.warn("Discarding STUN packet due to FINGERPRINT verification error from {}:{}: {}",
							receive.getAddress().getHostAddress(), receive.getPort(), e.getMessage());
					continue;
				}
			}

			if (receiveMH.equalTransactionID(expectedRequest)) {
				return receiveMH;
			}

			LOGGER.debug("Discarding STUN packet with non-matching transaction ID from {}:{}.",
					receive.getAddress().getHostAddress(), receive.getPort());
		}
	}
}
