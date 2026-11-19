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
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Timer;
import java.util.TimerTask;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.attribute.ChangeRequest;
import de.javawi.jstun.attribute.ErrorCode;
import de.javawi.jstun.attribute.MappedAddress;
import de.javawi.jstun.attribute.MessageAttribute;
import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.attribute.ResponseAddress;
import de.javawi.jstun.attribute.ResponsePort;
import de.javawi.jstun.attribute.Software;
import de.javawi.jstun.attribute.XorMappedAddress;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.util.UtilityException;

public class BindingLifetimeTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(BindingLifetimeTest.class);
	String stunServer;
	int port;
	int timeout = 300; // ms
	MappedAddress ma;
	Timer timer;
	DatagramSocket initialSocket;
	boolean useResponsePort = false;

	// start value for binary search - should be carefully choosen
	int upperBinarySearchLifetime = 345000; // ms
	int lowerBinarySearchLifetime = 0;
	int binarySearchLifetime = (upperBinarySearchLifetime + lowerBinarySearchLifetime) / 2;

	// lifetime value
	int lifetime = -1; // -1 means undefined.
	boolean completed = false;

	public BindingLifetimeTest(String stunServer, int port) {
		super();
		this.stunServer = stunServer;
		this.port = port;
		timer = new Timer(true);
	}

	public void test() throws UtilityException, SocketException, UnknownHostException, IOException,
			MessageAttributeParsingException, MessageAttributeException, MessageHeaderParsingException {
		initialSocket = new DatagramSocket();
		initialSocket.connect(InetAddress.getByName(stunServer), port);
		initialSocket.setSoTimeout(timeout);

		if (bindingCommunicationInitialSocket()) {
			return;
		}
		BindingLifetimeTask task = new BindingLifetimeTask();
		timer.schedule(task, binarySearchLifetime);
		LOGGER.debug("Timer scheduled initially: " + binarySearchLifetime + ".");
	}

	private boolean bindingCommunicationInitialSocket()
			throws UtilityException, IOException, MessageHeaderParsingException, MessageAttributeParsingException,
			MessageAttributeException {
		MessageHeader sendMH = new MessageHeader(MessageHeader.MessageHeaderType.BindingRequest);
		sendMH.generateTransactionID();
		ChangeRequest changeRequest = new ChangeRequest();
		sendMH.addMessageAttribute(changeRequest);
		sendMH.addMessageAttribute(Software.jstun());
		byte[] data = sendMH.getBytesWithFingerprint();

		DatagramPacket send = new DatagramPacket(data, data.length, InetAddress.getByName(stunServer), port);
		initialSocket.send(send);
		LOGGER.debug("Binding Request sent.");

		MessageHeader receiveMH = StunSocketReceiver.receiveMatching(initialSocket, sendMH, timeout);
		ma = (MappedAddress) receiveMH.getMessageAttribute(MessageAttribute.MessageAttributeType.MappedAddress);
		if (ma == null) {
			XorMappedAddress xma = (XorMappedAddress) receiveMH
					.getMessageAttribute(MessageAttribute.MessageAttributeType.XorMappedAddress);
			if (xma != null) {
				ma = new MappedAddress();
				ma.setAddress(xma.getAddress());
				ma.setPort(xma.getPort());
			}
		}
		ErrorCode ec = (ErrorCode) receiveMH.getMessageAttribute(MessageAttribute.MessageAttributeType.ErrorCode);
		if (ec != null) {
			LOGGER.debug("Message header contains an Errorcode message attribute.");
			return true;
		}
		if (ma == null) {
			LOGGER.debug("Response does not contain a Mapped Address message attribute.");
			return true;
		}
		return false;
	}

	public int getLifetime() {
		return lifetime;
	}

	public boolean isCompleted() {
		return completed;
	}

	/**
	 * When enabled, uses RFC 5780 §4.5 {@code RESPONSE-PORT} ({@code 0x0027}) instead
	 * of RFC 3489 {@code RESPONSE-ADDRESS} ({@code 0x0002}) for binding lifetime probes.
	 */
	public void setUseResponsePort(boolean useResponsePort) {
		this.useResponsePort = useResponsePort;
	}

	public boolean isUseResponsePort() {
		return useResponsePort;
	}

	public void setUpperBinarySearchLifetime(int upperBinarySearchLifetime) {
		this.upperBinarySearchLifetime = upperBinarySearchLifetime;
		binarySearchLifetime = (upperBinarySearchLifetime + lowerBinarySearchLifetime) / 2;
	}

	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

	public void close() {
		if (timer != null) {
			timer.cancel();
		}
		if (initialSocket != null && !initialSocket.isClosed()) {
			initialSocket.close();
		}
	}

	class BindingLifetimeTask extends TimerTask {

		public BindingLifetimeTask() {
			super();
		}

		public void run() {
			try {
				lifetimeQuery();
			} catch (Exception e) {
				LOGGER.error("Unhandled Exception. BindLifetimeTasks stopped: {}", e.getMessage(), e);
			}
		}

		public void lifetimeQuery() throws UtilityException, MessageAttributeException, MessageHeaderParsingException,
				MessageAttributeParsingException, IOException {
			try (DatagramSocket socket = new DatagramSocket()) {
				socket.connect(InetAddress.getByName(stunServer), port);
				socket.setSoTimeout(timeout);

				MessageHeader sendMH = new MessageHeader(MessageHeader.MessageHeaderType.BindingRequest);
				sendMH.generateTransactionID();
				ChangeRequest changeRequest = new ChangeRequest();
				sendMH.addMessageAttribute(changeRequest);
				sendMH.addMessageAttribute(Software.jstun());
				if (useResponsePort) {
					sendMH.addMessageAttribute(new ResponsePort(ma.getPort()));
				} else {
					ResponseAddress responseAddress = new ResponseAddress();
					responseAddress.setAddress(ma.getAddress());
					responseAddress.setPort(ma.getPort());
					sendMH.addMessageAttribute(responseAddress);
				}
				byte[] data = sendMH.getBytesWithFingerprint();

				DatagramPacket send = new DatagramPacket(data, data.length, InetAddress.getByName(stunServer), port);
				socket.send(send);
				LOGGER.debug("Binding Request sent.");

				MessageHeader receiveMH = StunSocketReceiver.receiveMatching(initialSocket, sendMH, timeout);
				ErrorCode ec = (ErrorCode) receiveMH
						.getMessageAttribute(MessageAttribute.MessageAttributeType.ErrorCode);
				if (ec != null) {
					LOGGER.debug("Message header contains errorcode message attribute.");
					return;
				}
				LOGGER.debug("Binding Response received.");
				if (upperBinarySearchLifetime == (lowerBinarySearchLifetime + 1)) {
					LOGGER.info("BindingLifetimeTest completed. UDP binding lifetime: {}.", binarySearchLifetime);
					completed = true;
					return;
				}
				lifetime = binarySearchLifetime;
				LOGGER.debug("Lifetime update: " + lifetime + ".");
				lowerBinarySearchLifetime = binarySearchLifetime;
				binarySearchLifetime = (upperBinarySearchLifetime + lowerBinarySearchLifetime) / 2;
				if (binarySearchLifetime > 0) {
					BindingLifetimeTask task = new BindingLifetimeTask();
					timer.schedule(task, binarySearchLifetime);
					LOGGER.debug("Timer scheduled: " + binarySearchLifetime + ".");
				} else {
					completed = true;
				}
			} catch (SocketTimeoutException ste) {
				LOGGER.debug("Read operation at query socket timeout.");
				if (upperBinarySearchLifetime == (lowerBinarySearchLifetime + 1)) {
					LOGGER.info("BindingLifetimeTest completed. UDP binding lifetime: {}.", binarySearchLifetime);
					completed = true;
					return;
				}
				upperBinarySearchLifetime = binarySearchLifetime;
				binarySearchLifetime = (upperBinarySearchLifetime + lowerBinarySearchLifetime) / 2;
				if (binarySearchLifetime > 0) {
					if (bindingCommunicationInitialSocket()) {
						return;
					}
					BindingLifetimeTask task = new BindingLifetimeTask();
					timer.schedule(task, binarySearchLifetime);
					LOGGER.debug("Timer scheduled: " + binarySearchLifetime + ".");
				} else {
					completed = true;
				}
			}
		}
	}
}
