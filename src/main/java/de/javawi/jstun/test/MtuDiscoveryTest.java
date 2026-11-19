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
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.attribute.MessageAttribute;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.attribute.Padding;
import de.javawi.jstun.attribute.Software;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.util.UtilityException;

/**
 * Implements UDP Path MTU probing using STUN as described in RFC 5780 Section 4.6
 * via binary search and the {@code PADDING} ({@code 0x0026}) attribute, with support
 * for Ethernet jumbo frames up to {@value #DEFAULT_MAX_MTU} bytes.
 */
public class MtuDiscoveryTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(MtuDiscoveryTest.class);
	public static final int DEFAULT_MIN_MTU = 576;
	/** RFC 8200 §5 / RFC 5780 §4.6 minimum link MTU for IPv6. */
	public static final int DEFAULT_MIN_IPV6_MTU = 1280;
	/** Default upper bound supports Ethernet jumbo frames (9000-byte MTU). */
	public static final int DEFAULT_MAX_MTU = 9000;
	private static final int IPV4_UDP_OVERHEAD = 28;
	private static final int IPV6_UDP_OVERHEAD = 48;

	private final InetAddress sourceIaddress;
	private final int sourcePort;
	private final String stunServer;
	private final int stunServerPort;
	private int timeoutInitValue = 300;
	private int maxWaitTimeMs = 2400;

	public MtuDiscoveryTest(InetAddress sourceIaddress, String stunServer, int stunServerPort) {
		this(sourceIaddress, 0, stunServer, stunServerPort);
	}

	public MtuDiscoveryTest(InetAddress sourceIaddress, int sourcePort, String stunServer, int stunServerPort) {
		this.sourceIaddress = sourceIaddress;
		this.sourcePort = sourcePort;
		this.stunServer = stunServer;
		this.stunServerPort = stunServerPort;
	}

	public void setTimeoutInitValue(int timeoutInitValue) {
		this.timeoutInitValue = timeoutInitValue;
	}

	public void setMaxWaitTimeMs(int maxWaitTimeMs) {
		this.maxWaitTimeMs = maxWaitTimeMs;
	}

	/**
	 * Performs RFC 5780 §4.6 UDP Path MTU probing across {@value #DEFAULT_MIN_MTU}..{@value #DEFAULT_MAX_MTU} bytes
	 * (supporting jumbo frames).
	 *
	 * @return the largest UDP/IP packet size in bytes that traversed the path, or {@code -1} if unsupported/blocked.
	 */
	public int test() throws UtilityException, SocketException, UnknownHostException, IOException,
			MessageAttributeParsingException, MessageHeaderParsingException {
		InetAddress primaryServerIP = StunSocketReceiver.resolveServerAddress(stunServer, sourceIaddress);
		int defaultMin = (primaryServerIP instanceof Inet6Address) ? DEFAULT_MIN_IPV6_MTU : DEFAULT_MIN_MTU;
		return test(defaultMin, DEFAULT_MAX_MTU);
	}

	/**
	 * Performs RFC 5780 §4.6 UDP Path MTU probing within {@code [minMtu, maxMtu]} bytes
	 * using binary search and the {@code PADDING} ({@code 0x0026}) attribute.
	 *
	 * @return the largest UDP/IP packet size in bytes that traversed the path, or {@code -1} if unsupported/blocked.
	 */
	public int test(int minMtu, int maxMtu) throws UtilityException, SocketException, UnknownHostException,
			IOException, MessageAttributeParsingException, MessageHeaderParsingException {
		if (minMtu <= 0 || maxMtu < minMtu) {
			throw new IllegalArgumentException("Invalid MTU bounds: minMtu=" + minMtu + ", maxMtu=" + maxMtu);
		}
		InetAddress primaryServerIP = StunSocketReceiver.resolveServerAddress(stunServer, sourceIaddress);
		int headerOverhead = (primaryServerIP instanceof Inet6Address) ? IPV6_UDP_OVERHEAD : IPV4_UDP_OVERHEAD;
		int recvBufSize = Math.max(10240, maxMtu + 1024);

		LOGGER.debug("Starting RFC 5780 MTU probing from {}:{} against {}:{} (range {}..{}).",
				sourceIaddress.getHostAddress(), sourcePort, stunServer, stunServerPort, minMtu, maxMtu);

		try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(sourceIaddress, sourcePort))) {
			socket.setReuseAddress(true);
			socket.setReceiveBufferSize(Math.max(65536, recvBufSize));
			socket.setSendBufferSize(Math.max(65536, recvBufSize));

			// Step 1: Capability probe with minimal PADDING (4 bytes) so legacy RFC 3489 servers fail fast with 420.
			MessageHeader capResp = sendPaddedBindingRequest(socket, primaryServerIP, stunServerPort, new Padding(4), recvBufSize);
			if (capResp == null) {
				LOGGER.warn("RFC 5780 MTU Discovery: no response to capability probe against {}:{}.", stunServer, stunServerPort);
				return -1;
			}
			if (capResp.getType() == MessageHeaderType.BindingErrorResponse
					|| capResp.getMessageAttribute(MessageAttribute.MessageAttributeType.ErrorCode) != null) {
				LOGGER.info("RFC 5780 MTU Discovery: server {}:{} rejected PADDING attribute; MTU probing unsupported.",
						stunServer, stunServerPort);
				return -1;
			}

			// Measure base STUN request size (without PADDING)
			MessageHeader baseReq = new MessageHeader(MessageHeaderType.BindingRequest);
			baseReq.generateTransactionID();
			baseReq.addMessageAttribute(Software.jstun());
			int baseStunLen = baseReq.getBytesWithFingerprint().length;

			// Step 2: Binary search over [minMtu, maxMtu]
			int low = minMtu;
			int high = maxMtu;
			int bestMtu = -1;
			while (low <= high) {
				int mid = low + (high - low) / 2;
				int rawPad = mid - headerOverhead - baseStunLen - 4;
				int alignedPad = (rawPad > 0) ? (rawPad / 4) * 4 : 0;
				Padding padding = new Padding(alignedPad);
				int actualProbeMtu = headerOverhead + baseStunLen + 4 + alignedPad;

				MessageHeader resp = sendPaddedBindingRequest(socket, primaryServerIP, stunServerPort, padding, recvBufSize);
				if (resp == null) {
					LOGGER.debug("RFC 5780 MTU probe {} bytes (target {}) timed out; lowering upper bound.", actualProbeMtu, mid);
					high = mid - 1;
				} else if (resp.getType() == MessageHeaderType.BindingErrorResponse
						|| resp.getMessageAttribute(MessageAttribute.MessageAttributeType.ErrorCode) != null) {
					LOGGER.info("RFC 5780 MTU probe {} bytes returned STUN error; stopping.", actualProbeMtu);
					return bestMtu;
				} else {
					LOGGER.debug("RFC 5780 MTU probe {} bytes succeeded.", actualProbeMtu);
					bestMtu = actualProbeMtu;
					low = mid + 1;
				}
			}

			LOGGER.info("RFC 5780 MTU Discovery completed against {}:{}: discoveredMtu={} bytes (range {}..{}).",
					stunServer, stunServerPort, bestMtu, minMtu, maxMtu);
			return bestMtu;
		}
	}

	private MessageHeader sendPaddedBindingRequest(DatagramSocket socket, InetAddress targetIP, int targetPort,
			Padding padding, int receiveBufferSize)
			throws UtilityException, IOException, MessageHeaderParsingException, MessageAttributeParsingException {
		int elapsed = 0;
		int timeout = timeoutInitValue;

		MessageHeader sendMH = new MessageHeader(MessageHeaderType.BindingRequest);
		sendMH.generateTransactionID();
		sendMH.addMessageAttribute(padding);
		sendMH.addMessageAttribute(Software.jstun());
		byte[] data = sendMH.getBytesWithFingerprint();

		while (true) {
			try {
				DatagramPacket send = new DatagramPacket(data, data.length, targetIP, targetPort);
				socket.send(send);
				LOGGER.debug("RFC 5780 MTU probe ({} STUN bytes) sent to {}:{}",
						data.length, targetIP.getHostAddress(), targetPort);

				return StunSocketReceiver.receiveMatching(socket, sendMH, timeout, receiveBufferSize);
			} catch (SocketTimeoutException ste) {
				if (elapsed < maxWaitTimeMs) {
					LOGGER.debug("RFC 5780 MTU probe timeout to {}:{}. Retrying...", targetIP.getHostAddress(), targetPort);
					elapsed += timeout;
					timeout = Math.min(timeout * 2, 1600);
				} else {
					LOGGER.debug("RFC 5780 MTU probe to {}:{} timed out after {} ms. Giving up.",
							targetIP.getHostAddress(), targetPort, elapsed);
					return null;
				}
			}
		}
	}
}
