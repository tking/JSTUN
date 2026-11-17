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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.attribute.ErrorCode;
import de.javawi.jstun.attribute.MappedResponseChangedSourceAddressReflectedFrom;
import de.javawi.jstun.attribute.MessageAttribute;
import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.attribute.Software;
import de.javawi.jstun.attribute.XorMappedAddress;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.util.UtilityException;

/**
 * Implements NAT Hairpinning Behavior discovery as described in RFC 5780.
 * <p>
 * Two local UDP sockets are opened: {@code socketA} discovers its external
 * mapped endpoint via a STUN Binding Request, and {@code socketB} sends a
 * STUN Binding Request directly to {@code socketA}'s external mapped IP and port.
 * If {@code socketA} receives that packet, the NAT supports hairpinning.
 */
public class HairpinningDiscoveryTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(HairpinningDiscoveryTest.class);
	private final InetAddress sourceIaddress;
	private final int sourcePort;
	private final String stunServer;
	private final int stunServerPort;
	private int timeoutInitValue = 300;
	private int maxWaitTimeMs = 1200;

	public HairpinningDiscoveryTest(InetAddress sourceIaddress, String stunServer, int stunServerPort) {
		this(sourceIaddress, 0, stunServer, stunServerPort);
	}

	public HairpinningDiscoveryTest(InetAddress sourceIaddress, int sourcePort, String stunServer, int stunServerPort) {
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
	 * Tests whether the NAT supports hairpinning.
	 *
	 * @return {@code Boolean.TRUE} if hairpinning is supported, {@code Boolean.FALSE} if
	 *         hairpinning packets are dropped, or {@code null} if the STUN server is unreachable
	 *         or returned an error.
	 */
	public Boolean test() throws UtilityException, SocketException, UnknownHostException, IOException,
			MessageAttributeParsingException, MessageAttributeException, MessageHeaderParsingException {
		InetAddress serverIP = InetAddress.getByName(stunServer);
		LOGGER.debug("Starting RFC 5780 hairpinning discovery from {}:{} against {}:{}.",
				sourceIaddress.getHostAddress(), sourcePort, stunServer, stunServerPort);

		try (DatagramSocket socketA = new DatagramSocket(new InetSocketAddress(sourceIaddress, sourcePort));
				DatagramSocket socketB = new DatagramSocket(new InetSocketAddress(sourceIaddress, 0))) {
			socketA.setReuseAddress(true);
			socketB.setReuseAddress(true);

			// Step 1: Discover socketA's external mapped endpoint from the STUN server.
			MessageHeader bindingReq = new MessageHeader(MessageHeaderType.BindingRequest);
			bindingReq.generateTransactionID();
			bindingReq.addMessageAttribute(Software.jstun());
			byte[] reqBytes = bindingReq.getBytesWithFingerprint();

			MessageHeader bindingResp = sendAndReceive(socketA, serverIP, stunServerPort, bindingReq, reqBytes);
			if (bindingResp == null) {
				LOGGER.warn("RFC 5780 Hairpinning Test: no response from STUN server {}:{}.", stunServer, stunServerPort);
				return null;
			}
			ErrorCode ec = (ErrorCode) bindingResp.getMessageAttribute(MessageAttribute.MessageAttributeType.ErrorCode);
			if (ec != null || bindingResp.getType() == MessageHeaderType.BindingErrorResponse) {
				LOGGER.warn("RFC 5780 Hairpinning Test: STUN server returned error {}.",
						(ec != null) ? ec.getResponseCode() : -1);
				return null;
			}

			MappedResponseChangedSourceAddressReflectedFrom mapped = extractMappedEndpoint(bindingResp);
			if (mapped == null) {
				LOGGER.warn("RFC 5780 Hairpinning Test: BindingResponse missing mapped address.");
				return null;
			}
			InetAddress mappedIp = mapped.getAddress().getInetAddress();
			int mappedPort = mapped.getPort();
			LOGGER.debug("RFC 5780 Hairpinning Test: socketA external endpoint is {}:{}.",
					mappedIp.getHostAddress(), mappedPort);

			// Step 2: Send a BindingRequest from socketB directly to socketA's external mapped endpoint.
			MessageHeader hairpinReq = new MessageHeader(MessageHeaderType.BindingRequest);
			hairpinReq.generateTransactionID();
			hairpinReq.addMessageAttribute(Software.jstun());
			byte[] hairpinBytes = hairpinReq.getBytesWithFingerprint();

			int elapsed = 0;
			int timeout = timeoutInitValue;
			while (true) {
				try {
					socketA.setSoTimeout(timeout);
					socketB.send(new DatagramPacket(hairpinBytes, hairpinBytes.length, mappedIp, mappedPort));

					MessageHeader received = new MessageHeader();
					while (!received.equalTransactionID(hairpinReq)) {
						DatagramPacket pkt = new DatagramPacket(new byte[512], 512);
						socketA.receive(pkt);
						received = MessageHeader.parseHeader(pkt.getData());
						received.parseAttributes(pkt.getData());
					}
					LOGGER.info("RFC 5780 Hairpinning Test against {}:{}: hairpinning SUPPORTED.", stunServer, stunServerPort);
					return Boolean.TRUE;
				} catch (SocketTimeoutException ste) {
					if (elapsed < maxWaitTimeMs) {
						elapsed += timeout;
						timeout = Math.min(timeout * 2, 800);
					} else {
						LOGGER.info("RFC 5780 Hairpinning Test against {}:{}: hairpinning NOT supported (timed out).",
								stunServer, stunServerPort);
						return Boolean.FALSE;
					}
				}
			}
		}
	}

	private MessageHeader sendAndReceive(DatagramSocket socket, InetAddress targetIP, int targetPort,
			MessageHeader sendMH, byte[] data)
			throws IOException, MessageHeaderParsingException, MessageAttributeParsingException {
		int elapsed = 0;
		int timeout = timeoutInitValue;
		while (true) {
			try {
				socket.setSoTimeout(timeout);
				socket.send(new DatagramPacket(data, data.length, targetIP, targetPort));
				MessageHeader receiveMH = new MessageHeader();
				while (!receiveMH.equalTransactionID(sendMH)) {
					DatagramPacket receive = new DatagramPacket(new byte[512], 512);
					socket.receive(receive);
					receiveMH = MessageHeader.parseHeader(receive.getData());
					receiveMH.parseAttributes(receive.getData());
				}
				return receiveMH;
			} catch (SocketTimeoutException ste) {
				if (elapsed < maxWaitTimeMs) {
					elapsed += timeout;
					timeout = Math.min(timeout * 2, 800);
				} else {
					return null;
				}
			}
		}
	}

	private MappedResponseChangedSourceAddressReflectedFrom extractMappedEndpoint(MessageHeader mh) {
		XorMappedAddress xma = (XorMappedAddress) mh.getMessageAttribute(MessageAttribute.MessageAttributeType.XorMappedAddress);
		if (xma != null) {
			return xma;
		}
		return (MappedResponseChangedSourceAddressReflectedFrom) mh
				.getMessageAttribute(MessageAttribute.MessageAttributeType.MappedAddress);
	}
}
