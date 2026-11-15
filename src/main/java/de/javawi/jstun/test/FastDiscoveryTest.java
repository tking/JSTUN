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

import de.javawi.jstun.attribute.ChangeRequest;
import de.javawi.jstun.attribute.ChangedAddress;
import de.javawi.jstun.attribute.ErrorCode;
import de.javawi.jstun.attribute.MappedAddress;
import de.javawi.jstun.attribute.MessageAttribute;
import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.attribute.OtherAddress;
import de.javawi.jstun.attribute.XorMappedAddress;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.util.UtilityException;

public class FastDiscoveryTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(FastDiscoveryTest.class);
	InetAddress sourceIaddress;
	int sourcePort;
	String stunServer;
	int stunServerPort;
	int timeoutInitValue = 300; // ms
	MappedAddress ma = null;
	ChangedAddress ca = null;
	boolean nodeNatted = true;
	DatagramSocket socketTest1 = null;
	DiscoveryInfo di = null;

	final static int UNINITIALIZED = -1;
	final static int ERROR = 0;
	final static int CONNECTION_ESTABLISHED_NO_ERROR = 1;
	final static int CONNECTION_TIMEOUT = 2;

	public FastDiscoveryTest(InetAddress sourceIaddress, String stunServer, int stunServerPort) {
		this(sourceIaddress, 0, stunServer, stunServerPort);
	}

	public FastDiscoveryTest(InetAddress sourceIaddress, int sourcePort, String stunServer, int stunServerPort) {
		this.sourceIaddress = sourceIaddress;
		this.sourcePort = sourcePort;
		this.stunServer = stunServer;
		this.stunServerPort = stunServerPort;
	}

	public DiscoveryInfo test() throws UtilityException, SocketException, UnknownHostException, IOException,
			MessageAttributeParsingException, MessageAttributeException, MessageHeaderParsingException {
		ma = null;
		ca = null;
		nodeNatted = true;
		socketTest1 = null;
		di = new DiscoveryInfo(sourceIaddress);

		int returnTest2 = UNINITIALIZED;
		int returnTest3 = UNINITIALIZED;

		try {
			// run test1 and test2 in parallel
			// run test1Redo and test3 in parallel

			Test1Thread t1t = new Test1Thread(this);
			t1t.start();

			Test2Thread t2t = new Test2Thread(this);
			t2t.start();

			while (t1t.isAlive() || t2t.isAlive()) {
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			}

			boolean returnTest1 = t1t.getReturnTest1();

			if (returnTest1) {
				returnTest2 = t2t.getReturnTest2();

				// evaluate result of test1 and test2
				if (returnTest2 != UNINITIALIZED) {
					if ((returnTest2 == CONNECTION_ESTABLISHED_NO_ERROR) && (!nodeNatted)) {
						di.setOpenAccess();
					}
					if ((returnTest2 == CONNECTION_ESTABLISHED_NO_ERROR) && (nodeNatted)) {
						di.setFullCone();
					}
					if ((returnTest2 == CONNECTION_TIMEOUT) && (!nodeNatted)) {
						di.setSymmetricUDPFirewall();
					}
				}

				if ((returnTest2 == CONNECTION_TIMEOUT) && (nodeNatted)) {
					// start test1redo and test3 in parallel

					Test1RedoThread t1rt = new Test1RedoThread(this);
					t1rt.start();

					Test3Thread t3t = new Test3Thread(this);
					t3t.start();

					while (t1rt.isAlive() || t3t.isAlive()) {
						try {
							Thread.sleep(100);
						} catch (InterruptedException e) {
							Thread.currentThread().interrupt();
						}
					}

					if (t1rt.getReturnTest1Redo()) {
						returnTest3 = t3t.getReturnTest3();

						// evaluate test3
						if (returnTest3 != UNINITIALIZED) {
							if ((returnTest3 == CONNECTION_ESTABLISHED_NO_ERROR) && (nodeNatted)) {
								di.setRestrictedCone();
							}
							if (returnTest3 == CONNECTION_TIMEOUT) {
								di.setPortRestrictedCone();
							}
						}
					}
				}
			}
		} finally {
			if (socketTest1 != null) {
				socketTest1.close();
			}
		}

		return di;
	}

	private MappedAddress extractMappedAddress(MessageHeader receiveMH) throws MessageAttributeException {
		XorMappedAddress xma = (XorMappedAddress) receiveMH
				.getMessageAttribute(MessageAttribute.MessageAttributeType.XorMappedAddress);
		if (xma != null) {
			MappedAddress converted = new MappedAddress();
			converted.setAddress(xma.getAddress());
			converted.setPort(xma.getPort());
			return converted;
		}
		return (MappedAddress) receiveMH.getMessageAttribute(MessageAttribute.MessageAttributeType.MappedAddress);
	}

	private ChangedAddress extractChangedAddress(MessageHeader receiveMH) throws MessageAttributeException {
		ChangedAddress changed = (ChangedAddress) receiveMH
				.getMessageAttribute(MessageAttribute.MessageAttributeType.ChangedAddress);
		if (changed != null) {
			return changed;
		}
		OtherAddress oa = (OtherAddress) receiveMH
				.getMessageAttribute(MessageAttribute.MessageAttributeType.OtherAddress);
		if (oa != null) {
			ChangedAddress converted = new ChangedAddress();
			converted.setAddress(oa.getAddress());
			converted.setPort(oa.getPort());
			return converted;
		}
		return null;
	}

	private boolean test1() throws UtilityException, SocketException, UnknownHostException, IOException,
			MessageAttributeParsingException, MessageAttributeException, MessageHeaderParsingException {
		int timeSinceFirstTransmission = 0;
		int timeout = timeoutInitValue;
		InetAddress serverAddress = InetAddress.getByName(stunServer);
		if (socketTest1 != null) {
			socketTest1.close();
		}
		socketTest1 = new DatagramSocket(new InetSocketAddress(sourceIaddress, sourcePort));
		socketTest1.setReuseAddress(true);

		MessageHeader sendMH = new MessageHeader(MessageHeader.MessageHeaderType.BindingRequest);
		sendMH.generateTransactionID();

		ChangeRequest changeRequest = new ChangeRequest();
		sendMH.addMessageAttribute(changeRequest);

		byte[] data = sendMH.getBytes();

		while (true) {
			try {
				// Test 1 including response on unconnected socketTest1
				socketTest1.setSoTimeout(timeout);
				DatagramPacket send = new DatagramPacket(data, data.length, serverAddress, stunServerPort);
				socketTest1.send(send);
				LOGGER.debug("Test 1: Binding Request sent.");

				MessageHeader receiveMH = new MessageHeader();
				while (!(receiveMH.equalTransactionID(sendMH))) {
					DatagramPacket receive = new DatagramPacket(new byte[512], 512);
					socketTest1.receive(receive);
					receiveMH = MessageHeader.parseHeader(receive.getData());
					receiveMH.parseAttributes(receive.getData());
				}
				ma = extractMappedAddress(receiveMH);
				ca = extractChangedAddress(receiveMH);
				ErrorCode ec = (ErrorCode) receiveMH
						.getMessageAttribute(MessageAttribute.MessageAttributeType.ErrorCode);
				if (ec != null) {
					di.setError(ec.getResponseCode(), ec.getReason());
					LOGGER.debug("Message header contains an Errorcode message attribute.");
					return false;
				}
				if ((ma == null) || (ca == null)) {
					di.setError(700,
							"The server is sending an incomplete response (Mapped Address and Changed Address message attributes are missing). The client should not retry.");
					LOGGER.debug("Response does not contain a Mapped Address or Changed Address message attribute.");
					return false;
				} else {
					di.setPublicIP(ma.getAddress().getInetAddress());
					di.setPublicPort(ma.getPort());
					if ((ma.getPort() == socketTest1.getLocalPort())
							&& (ma.getAddress().getInetAddress().equals(socketTest1.getLocalAddress()))) {
						LOGGER.debug("Node is not natted.");
						nodeNatted = false;
					} else {
						LOGGER.debug("Node is natted.");
					}
					return true;
				}
			} catch (SocketTimeoutException ste) {
				if (timeSinceFirstTransmission < 300) {
					LOGGER.debug("Test 1: Socket timeout while receiving the response.");
					timeSinceFirstTransmission += timeout;
				} else {
					// node is not capable of udp communication
					LOGGER.debug(
							"Test 1: Socket timeout while receiving the response. Maximum retry limit exceed. Give up.");
					di.setBlockedUDP();
					LOGGER.debug("Node is not capable of UDP communication.");
					return false;
				}
			}
		}
	}

	private int test2() throws UtilityException, SocketException, UnknownHostException, IOException,
			MessageAttributeParsingException, MessageAttributeException, MessageHeaderParsingException {
		int timeSinceFirstTransmission = 0;
		int timeout = timeoutInitValue;
		InetAddress serverAddress = InetAddress.getByName(stunServer);

		MessageHeader sendMH = new MessageHeader(MessageHeader.MessageHeaderType.BindingRequest);
		sendMH.generateTransactionID();

		ChangeRequest changeRequest = new ChangeRequest();
		changeRequest.setChangeIP();
		changeRequest.setChangePort();
		sendMH.addMessageAttribute(changeRequest);

		byte[] data = sendMH.getBytes();

		try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(sourceIaddress, 0))) {
			socket.setReuseAddress(true);
			while (true) {
				try {
					// Single unconnected socket so response from alternate IP/port is received without close/re-bind race
					socket.setSoTimeout(timeout);
					DatagramPacket send = new DatagramPacket(data, data.length, serverAddress, stunServerPort);
					socket.send(send);
					LOGGER.debug("Test 2: Binding Request sent.");

					MessageHeader receiveMH = new MessageHeader();
					while (!(receiveMH.equalTransactionID(sendMH))) {
						DatagramPacket receive = new DatagramPacket(new byte[512], 512);
						socket.receive(receive);
						receiveMH = MessageHeader.parseHeader(receive.getData());
						receiveMH.parseAttributes(receive.getData());
					}
					ErrorCode ec = (ErrorCode) receiveMH
							.getMessageAttribute(MessageAttribute.MessageAttributeType.ErrorCode);
					if (ec != null) {
						di.setError(ec.getResponseCode(), ec.getReason());
						LOGGER.debug("Message header contains an Errorcode message attribute.");
						return ERROR;
					}
					return CONNECTION_ESTABLISHED_NO_ERROR;
				} catch (SocketTimeoutException ste) {
					if (timeSinceFirstTransmission < 300) {
						LOGGER.debug("Test 2: Socket timeout while receiving the response.");
						timeSinceFirstTransmission += timeout;
					} else {
						LOGGER.debug(
								"Test 2: Socket timeout while receiving the response. Maximum retry limit exceed. Give up.");
						return CONNECTION_TIMEOUT;
					}
				}
			}
		}
	}

	private boolean test1Redo() throws UtilityException, SocketException, UnknownHostException, IOException,
			MessageAttributeParsingException, MessageAttributeException, MessageHeaderParsingException {
		int timeSinceFirstTransmission = 0;
		int timeout = timeoutInitValue;
		InetAddress changedServerAddress = ca.getAddress().getInetAddress();
		int changedServerPort = ca.getPort();

		MessageHeader sendMH = new MessageHeader(MessageHeader.MessageHeaderType.BindingRequest);
		sendMH.generateTransactionID();

		ChangeRequest changeRequest = new ChangeRequest();
		sendMH.addMessageAttribute(changeRequest);

		byte[] data = sendMH.getBytes();

		while (true) {
			// redo test 1 with address and port as offered in the changed-address message
			// attribute
			try {
				// Test 1 with changed port and address values on unconnected socketTest1
				socketTest1.setSoTimeout(timeout);
				DatagramPacket send = new DatagramPacket(data, data.length, changedServerAddress, changedServerPort);
				socketTest1.send(send);
				LOGGER.debug("Test 1 redo with changed address: Binding Request sent.");

				MessageHeader receiveMH = new MessageHeader();
				while (!(receiveMH.equalTransactionID(sendMH))) {
					DatagramPacket receive = new DatagramPacket(new byte[512], 512);
					socketTest1.receive(receive);
					receiveMH = MessageHeader.parseHeader(receive.getData());
					receiveMH.parseAttributes(receive.getData());
				}
				MappedAddress ma2 = extractMappedAddress(receiveMH);
				ErrorCode ec = (ErrorCode) receiveMH
						.getMessageAttribute(MessageAttribute.MessageAttributeType.ErrorCode);
				if (ec != null) {
					di.setError(ec.getResponseCode(), ec.getReason());
					LOGGER.debug("Message header contains an Errorcode message attribute.");
					return false;
				}
				if (ma2 == null) {
					di.setError(700,
							"The server is sending an incomplete response (Mapped Address message attribute is missing). The client should not retry.");
					LOGGER.debug("Response does not contain a Mapped Address message attribute.");
					return false;
				} else {
					if ((ma.getPort() != ma2.getPort())
							|| (!(ma.getAddress().getInetAddress().equals(ma2.getAddress().getInetAddress())))) {
						di.setSymmetric();
						LOGGER.debug("Node is behind a symmetric NAT.");
						return false;
					}
				}
				return true;
			} catch (SocketTimeoutException ste2) {
				if (timeSinceFirstTransmission < 300) {
					LOGGER.debug("Test 1 redo with changed address: Socket timeout while receiving the response.");
					timeSinceFirstTransmission += timeout;
				} else {
					LOGGER.debug(
							"Test 1 redo with changed address: Socket timeout while receiving the response.  Maximum retry limit exceed. Give up.");
					return false;
				}
			}
		}
	}

	private int test3() throws UtilityException, SocketException, UnknownHostException, IOException,
			MessageAttributeParsingException, MessageAttributeException, MessageHeaderParsingException {
		int timeSinceFirstTransmission = 0;
		int timeout = timeoutInitValue;
		InetAddress serverAddress = InetAddress.getByName(stunServer);

		MessageHeader sendMH = new MessageHeader(MessageHeader.MessageHeaderType.BindingRequest);
		sendMH.generateTransactionID();

		ChangeRequest changeRequest = new ChangeRequest();
		changeRequest.setChangePort();
		sendMH.addMessageAttribute(changeRequest);

		byte[] data = sendMH.getBytes();

		try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(sourceIaddress, 0))) {
			socket.setReuseAddress(true);
			while (true) {
				try {
					// Single unconnected socket so response from changed port is received without close/re-bind race
					socket.setSoTimeout(timeout);
					DatagramPacket send = new DatagramPacket(data, data.length, serverAddress, stunServerPort);
					socket.send(send);
					LOGGER.debug("Test 3: Binding Request sent.");

					MessageHeader receiveMH = new MessageHeader();
					while (!(receiveMH.equalTransactionID(sendMH))) {
						DatagramPacket receive = new DatagramPacket(new byte[512], 512);
						socket.receive(receive);
						receiveMH = MessageHeader.parseHeader(receive.getData());
						receiveMH.parseAttributes(receive.getData());
					}
					ErrorCode ec = (ErrorCode) receiveMH
							.getMessageAttribute(MessageAttribute.MessageAttributeType.ErrorCode);
					if (ec != null) {
						di.setError(ec.getResponseCode(), ec.getReason());
						LOGGER.debug("Message header contains an Errorcode message attribute.");
						return ERROR;
					}
					return CONNECTION_ESTABLISHED_NO_ERROR;
				} catch (SocketTimeoutException ste) {
					if (timeSinceFirstTransmission < 300) {
						LOGGER.debug("Test 3: Socket timeout while receiving the response.");
						timeSinceFirstTransmission += timeout;
					} else {
						LOGGER.debug(
								"Test 3: Socket timeout while receiving the response. Maximum retry limit exceed. Give up.");
						return CONNECTION_TIMEOUT;
					}
				}
			}
		}
	}

	public class Test1Thread extends Thread {
		private FastDiscoveryTest fdt;
		private boolean returnTest1;

		public Test1Thread(FastDiscoveryTest fdt) {
			this.fdt = fdt;
		}

		@Override
		public void run() {
			try {
				returnTest1 = fdt.test1();
			} catch (Exception e) {
			}
		}

		public boolean getReturnTest1() {
			return returnTest1;
		}
	}

	public class Test2Thread extends Thread {
		private FastDiscoveryTest fdt;
		private int returnTest2 = UNINITIALIZED;

		public Test2Thread(FastDiscoveryTest fdt) {
			this.fdt = fdt;
		}

		@Override
		public void run() {
			try {
				returnTest2 = fdt.test2();
			} catch (Exception e) {
			}
		}

		public int getReturnTest2() {
			return returnTest2;
		}
	}

	public class Test1RedoThread extends Thread {
		private FastDiscoveryTest fdt;
		private boolean returnTest1Redo;

		public Test1RedoThread(FastDiscoveryTest fdt) {
			this.fdt = fdt;
		}

		@Override
		public void run() {
			try {
				returnTest1Redo = fdt.test1Redo();
			} catch (Exception e) {
			}
		}

		public boolean getReturnTest1Redo() {
			return returnTest1Redo;
		}
	}

	public class Test3Thread extends Thread {
		private FastDiscoveryTest fdt;
		private int returnTest3 = UNINITIALIZED;

		public Test3Thread(FastDiscoveryTest fdt) {
			this.fdt = fdt;
		}

		@Override
		public void run() {
			try {
				returnTest3 = fdt.test3();
			} catch (Exception e) {
			}
		}

		public int getReturnTest3() {
			return returnTest3;
		}
	}
}
