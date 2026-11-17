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

import de.javawi.jstun.attribute.ChangeRequest;
import de.javawi.jstun.attribute.ChangedAddress;
import de.javawi.jstun.attribute.ErrorCode;
import de.javawi.jstun.attribute.MappedAddress;
import de.javawi.jstun.attribute.MappedResponseChangedSourceAddressReflectedFrom;
import de.javawi.jstun.attribute.MessageAttribute;
import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.attribute.OtherAddress;
import de.javawi.jstun.attribute.Padding;
import de.javawi.jstun.attribute.Software;
import de.javawi.jstun.attribute.XorMappedAddress;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.test.DiscoveryInfo.FilteringBehavior;
import de.javawi.jstun.test.DiscoveryInfo.MappingBehavior;
import de.javawi.jstun.util.UtilityException;

/*
 * Implements NAT Behavior Discovery Using STUN as specified in RFC 5780
 * (Sections 4.3 Mapping Behavior and 4.4 Filtering Behavior).
 */
public class NatBehaviorDiscoveryTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(NatBehaviorDiscoveryTest.class);
	public static final int DEFAULT_MIN_MTU = 576;
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

	public NatBehaviorDiscoveryTest(InetAddress sourceIaddress, String stunServer, int stunServerPort) {
		this(sourceIaddress, 0, stunServer, stunServerPort);
	}

	public NatBehaviorDiscoveryTest(InetAddress sourceIaddress, int sourcePort, String stunServer, int stunServerPort) {
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

	public DiscoveryInfo test() throws UtilityException, SocketException, UnknownHostException, IOException,
			MessageAttributeParsingException, MessageAttributeException, MessageHeaderParsingException {
		return test(false);
	}

	/**
	 * Runs RFC 5780 NAT behavior discovery and optionally performs RFC 5780 §4.6
	 * MTU probing (supporting up to 9000-byte jumbo frames).
	 */
	public DiscoveryInfo test(boolean probeMtu) throws UtilityException, SocketException, UnknownHostException, IOException,
			MessageAttributeParsingException, MessageAttributeException, MessageHeaderParsingException {
		DiscoveryInfo di = runBehaviorDiscovery();
		if (probeMtu && !di.isBlockedUDP() && !di.isError()) {
			int mtu = discoverMtu();
			if (mtu > 0) {
				di.setDiscoveredMtu(mtu);
			}
		}
		return di;
	}

	private DiscoveryInfo runBehaviorDiscovery() throws UtilityException, SocketException, UnknownHostException, IOException,
			MessageAttributeParsingException, MessageAttributeException, MessageHeaderParsingException {
		DiscoveryInfo di = new DiscoveryInfo(sourceIaddress);
		InetAddress primaryServerIP = InetAddress.getByName(stunServer);
		LOGGER.debug("Starting RFC 5780 NAT behavior discovery from {}:{} against STUN server {}:{}.",
				sourceIaddress.getHostAddress(), sourcePort, stunServer, stunServerPort);

		try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(sourceIaddress, sourcePort))) {
			socket.setReuseAddress(true);

			// RFC 5780 Section 4.3: Mapping Behavior - Test I
			MessageHeader response1 = sendBindingRequest(socket, primaryServerIP, stunServerPort, null);
			if (response1 == null) {
				LOGGER.debug("RFC 5780 Mapping Test I: No response received. Node is not capable of UDP communication.");
				di.setBlockedUDP();
				return di;
			}
			ErrorCode ec = (ErrorCode) response1.getMessageAttribute(MessageAttribute.MessageAttributeType.ErrorCode);
			if (ec != null) {
				LOGGER.warn("RFC 5780 Mapping Test I: Server returned error code {} ({}).", ec.getResponseCode(), ec.getReason());
				di.setError(ec.getResponseCode(), ec.getReason());
				return di;
			}

			MappedResponseChangedSourceAddressReflectedFrom ma1 = extractMappedAddress(response1);
			MappedResponseChangedSourceAddressReflectedFrom oa = extractOtherAddress(response1);
			if (ma1 == null) {
				LOGGER.warn("RFC 5780 Mapping Test I: Server response is missing MAPPED-ADDRESS / XOR-MAPPED-ADDRESS.");
				di.setError(700, "Server response is missing MAPPED-ADDRESS / XOR-MAPPED-ADDRESS.");
				return di;
			}

			di.setPublicIP(ma1.getAddress().getInetAddress());
			di.setPublicPort(ma1.getPort());
			LOGGER.debug("RFC 5780 Mapping Test I: Mapped public endpoint is {}:{}.",
					di.getPublicIP().getHostAddress(), di.getPublicPort());

			boolean isDirect = (ma1.getPort() == socket.getLocalPort())
					&& ma1.getAddress().getInetAddress().equals(socket.getLocalAddress());
			if (isDirect) {
				di.setMappingBehavior(MappingBehavior.DIRECT);
				LOGGER.debug("RFC 5780 Mapping Behavior: DIRECT.");
			} else if (oa != null) {
				InetAddress alternateServerIP = oa.getAddress().getInetAddress();
				int alternateServerPort = oa.getPort();

				// RFC 5780 Section 4.3: Mapping Behavior - Test II (Alternate IP, Primary Port)
				LOGGER.debug("RFC 5780 Mapping Test II: Sending Binding Request to alternate IP {}:{} (primary port).",
						alternateServerIP.getHostAddress(), stunServerPort);
				MessageHeader response2 = sendBindingRequest(socket, alternateServerIP, stunServerPort, null);
				if (response2 != null) {
					MappedResponseChangedSourceAddressReflectedFrom ma2 = extractMappedAddress(response2);
					if (ma2 != null) {
						if (sameEndpoint(ma1, ma2)) {
							di.setMappingBehavior(MappingBehavior.ENDPOINT_INDEPENDENT);
							LOGGER.debug("RFC 5780 Mapping Behavior: ENDPOINT_INDEPENDENT.");
						} else {
							// RFC 5780 Section 4.3: Mapping Behavior - Test III (Alternate IP, Alternate Port)
							LOGGER.debug("RFC 5780 Mapping Test III: Sending Binding Request to alternate IP and alternate port {}:{}.",
									alternateServerIP.getHostAddress(), alternateServerPort);
							MessageHeader response3 = sendBindingRequest(socket, alternateServerIP, alternateServerPort, null);
							if (response3 != null) {
								MappedResponseChangedSourceAddressReflectedFrom ma3 = extractMappedAddress(response3);
								if (ma3 != null) {
									if (sameEndpoint(ma2, ma3)) {
										di.setMappingBehavior(MappingBehavior.ADDRESS_DEPENDENT);
										LOGGER.debug("RFC 5780 Mapping Behavior: ADDRESS_DEPENDENT.");
									} else {
										di.setMappingBehavior(MappingBehavior.ADDRESS_AND_PORT_DEPENDENT);
										LOGGER.debug("RFC 5780 Mapping Behavior: ADDRESS_AND_PORT_DEPENDENT.");
									}
								}
							}
						}
					}
				}
			}

			// RFC 5780 Section 4.4: Filtering Behavior - Test II (Change IP and Change Port)
			if (oa != null) {
				ChangeRequest crBoth = new ChangeRequest();
				crBoth.setChangeIP();
				crBoth.setChangePort();
				LOGGER.debug("RFC 5780 Filtering Test II: Sending Binding Request with changeIP=true, changePort=true.");
				MessageHeader filterResp2 = sendBindingRequest(socket, primaryServerIP, stunServerPort, crBoth);
				if (filterResp2 != null) {
					di.setFilteringBehavior(FilteringBehavior.ENDPOINT_INDEPENDENT);
					LOGGER.debug("RFC 5780 Filtering Behavior: ENDPOINT_INDEPENDENT.");
				} else {
					// RFC 5780 Section 4.4: Filtering Behavior - Test III (Change Port only)
					ChangeRequest crPort = new ChangeRequest();
					crPort.setChangePort();
					LOGGER.debug("RFC 5780 Filtering Test III: Sending Binding Request with changeIP=false, changePort=true.");
					MessageHeader filterResp3 = sendBindingRequest(socket, primaryServerIP, stunServerPort, crPort);
					if (filterResp3 != null) {
						di.setFilteringBehavior(FilteringBehavior.ADDRESS_DEPENDENT);
						LOGGER.debug("RFC 5780 Filtering Behavior: ADDRESS_DEPENDENT.");
					} else {
						di.setFilteringBehavior(FilteringBehavior.ADDRESS_AND_PORT_DEPENDENT);
						LOGGER.debug("RFC 5780 Filtering Behavior: ADDRESS_AND_PORT_DEPENDENT.");
					}
				}
			}

			// Populate legacy DiscoveryInfo fields for backward compatibility
			populateLegacyClassification(di, isDirect);
			LOGGER.info("RFC 5780 NAT behavior discovery completed for {}: mapping={}, filtering={}.",
					sourceIaddress.getHostAddress(), di.getMappingBehavior(), di.getFilteringBehavior());
		}
		return di;
	}

	private void populateLegacyClassification(DiscoveryInfo di, boolean isDirect) {
		if (isDirect) {
			if (di.getFilteringBehavior() == FilteringBehavior.ENDPOINT_INDEPENDENT) {
				di.setOpenAccess();
			} else if (di.getFilteringBehavior() != FilteringBehavior.UNKNOWN) {
				di.setSymmetricUDPFirewall();
			}
			return;
		}
		if (di.getMappingBehavior() == MappingBehavior.ENDPOINT_INDEPENDENT) {
			if (di.getFilteringBehavior() == FilteringBehavior.ENDPOINT_INDEPENDENT) {
				di.setFullCone();
			} else if (di.getFilteringBehavior() == FilteringBehavior.ADDRESS_DEPENDENT) {
				di.setRestrictedCone();
			} else if (di.getFilteringBehavior() == FilteringBehavior.ADDRESS_AND_PORT_DEPENDENT) {
				di.setPortRestrictedCone();
			}
		} else if (di.getMappingBehavior() == MappingBehavior.ADDRESS_DEPENDENT
				|| di.getMappingBehavior() == MappingBehavior.ADDRESS_AND_PORT_DEPENDENT) {
			di.setSymmetric();
		}
	}

	private boolean sameEndpoint(MappedResponseChangedSourceAddressReflectedFrom a,
			MappedResponseChangedSourceAddressReflectedFrom b) {
		return (a.getPort() == b.getPort()) && a.getAddress().equals(b.getAddress());
	}

	private MappedResponseChangedSourceAddressReflectedFrom extractMappedAddress(MessageHeader mh) {
		XorMappedAddress xma = (XorMappedAddress) mh
				.getMessageAttribute(MessageAttribute.MessageAttributeType.XorMappedAddress);
		if (xma != null) {
			return xma;
		}
		return (MappedAddress) mh.getMessageAttribute(MessageAttribute.MessageAttributeType.MappedAddress);
	}

	private MappedResponseChangedSourceAddressReflectedFrom extractOtherAddress(MessageHeader mh) {
		OtherAddress oa = (OtherAddress) mh.getMessageAttribute(MessageAttribute.MessageAttributeType.OtherAddress);
		if (oa != null) {
			return oa;
		}
		return (ChangedAddress) mh.getMessageAttribute(MessageAttribute.MessageAttributeType.ChangedAddress);
	}

	/**
	 * Performs RFC 5780 §4.6 UDP Path MTU probing across {@value #DEFAULT_MIN_MTU}..{@value #DEFAULT_MAX_MTU} bytes
	 * (supporting jumbo frames) using binary search and the PADDING (0x0026) attribute.
	 *
	 * @return the largest UDP/IP packet size in bytes that traversed the path, or {@code -1} if unsupported/blocked.
	 */
	public int discoverMtu() throws UtilityException, SocketException, UnknownHostException, IOException,
			MessageAttributeParsingException, MessageHeaderParsingException {
		return discoverMtu(DEFAULT_MIN_MTU, DEFAULT_MAX_MTU);
	}

	/**
	 * Performs RFC 5780 §4.6 UDP Path MTU probing within {@code [minMtu, maxMtu]} bytes
	 * using binary search and the PADDING (0x0026) attribute.
	 *
	 * @return the largest UDP/IP packet size in bytes that traversed the path, or {@code -1} if unsupported/blocked.
	 */
	public int discoverMtu(int minMtu, int maxMtu) throws UtilityException, SocketException, UnknownHostException,
			IOException, MessageAttributeParsingException, MessageHeaderParsingException {
		if (minMtu <= 0 || maxMtu < minMtu) {
			throw new IllegalArgumentException("Invalid MTU bounds: minMtu=" + minMtu + ", maxMtu=" + maxMtu);
		}
		InetAddress primaryServerIP = InetAddress.getByName(stunServer);
		int headerOverhead = (primaryServerIP instanceof Inet6Address) ? IPV6_UDP_OVERHEAD : IPV4_UDP_OVERHEAD;
		int recvBufSize = Math.max(10240, maxMtu + 1024);

		try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(sourceIaddress, sourcePort))) {
			socket.setReuseAddress(true);
			socket.setReceiveBufferSize(Math.max(65536, recvBufSize));
			socket.setSendBufferSize(Math.max(65536, recvBufSize));

			// Step 1: Capability probe with minimal PADDING (4 bytes) so legacy RFC 3489 servers fail fast with 420.
			MessageHeader capResp = sendBindingRequest(socket, primaryServerIP, stunServerPort, null, new Padding(4), recvBufSize);
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

				MessageHeader resp = sendBindingRequest(socket, primaryServerIP, stunServerPort, null, padding, recvBufSize);
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

	private MessageHeader sendBindingRequest(DatagramSocket socket, InetAddress targetIP, int targetPort,
			ChangeRequest changeRequest)
			throws UtilityException, IOException, MessageHeaderParsingException, MessageAttributeParsingException {
		return sendBindingRequest(socket, targetIP, targetPort, changeRequest, null, 512);
	}

	private MessageHeader sendBindingRequest(DatagramSocket socket, InetAddress targetIP, int targetPort,
			ChangeRequest changeRequest, Padding padding, int receiveBufferSize)
			throws UtilityException, IOException, MessageHeaderParsingException, MessageAttributeParsingException {
		int elapsed = 0;
		int timeout = timeoutInitValue;

		MessageHeader sendMH = new MessageHeader(MessageHeader.MessageHeaderType.BindingRequest);
		sendMH.generateTransactionID();
		if (changeRequest != null) {
			sendMH.addMessageAttribute(changeRequest);
		}
		if (padding != null) {
			sendMH.addMessageAttribute(padding);
		}
		sendMH.addMessageAttribute(Software.jstun());
		byte[] data = sendMH.getBytesWithFingerprint();

		while (true) {
			try {
				socket.setSoTimeout(timeout);
				DatagramPacket send = new DatagramPacket(data, data.length, targetIP, targetPort);
				socket.send(send);
				LOGGER.debug("RFC 5780 Binding Request sent to " + targetIP.getHostAddress() + ":" + targetPort);

				MessageHeader receiveMH = new MessageHeader();
				while (!receiveMH.equalTransactionID(sendMH)) {
					DatagramPacket receive = new DatagramPacket(new byte[receiveBufferSize], receiveBufferSize);
					socket.receive(receive);
					receiveMH = MessageHeader.parseHeader(receive.getData());
					receiveMH.parseAttributes(receive.getData());
				}
				return receiveMH;
			} catch (SocketTimeoutException ste) {
				if (elapsed < maxWaitTimeMs) {
					LOGGER.debug("RFC 5780 Binding Request timeout to {}:{}. Retrying...", targetIP.getHostAddress(), targetPort);
					elapsed += timeout;
					timeout = Math.min(timeout * 2, 1600);
				} else {
					LOGGER.debug("RFC 5780 Binding Request to {}:{} timed out after {} ms. Giving up.",
							targetIP.getHostAddress(), targetPort, elapsed);
					return null;
				}
			}
		}
	}
}
