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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.attribute.Software;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;

public class StunSocketReceiverTest {

	@Test
	public void testDiscardsMalformedCorruptFingerprintAndTruncatedThenReturnsValidResponse() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");

		MessageHeader req = new MessageHeader(MessageHeaderType.BindingRequest);
		req.generateTransactionID();

		MessageHeader validResp = new MessageHeader(MessageHeaderType.BindingResponse);
		validResp.setTransactionID(req.getTransactionID());
		validResp.addMessageAttribute(Software.jstun());
		byte[] validBytes = validResp.getBytesWithFingerprint();

		// Corrupt FINGERPRINT packet with matching transaction ID
		byte[] corruptFpBytes = validBytes.clone();
		corruptFpBytes[corruptFpBytes.length - 1] ^= 0x01;

		// Truncated packet claiming larger header length than actual UDP payload
		byte[] truncated = new byte[20];
		System.arraycopy(validBytes, 0, truncated, 0, 20);
		// Header claims > 0 attribute bytes, but UDP payload is only 20 bytes

		// Non-STUN garbage packet
		byte[] garbage = new byte[] { (byte) 0xFF, (byte) 0xFE, 0x01, 0x02 };

		try (DatagramSocket receiver = new DatagramSocket(0, loopback);
				DatagramSocket sender = new DatagramSocket(0, loopback)) {
			int targetPort = receiver.getLocalPort();

			// Queue malformed, truncated, corrupt-fingerprint, and finally valid packets
			sender.send(new DatagramPacket(garbage, garbage.length, loopback, targetPort));
			sender.send(new DatagramPacket(truncated, truncated.length, loopback, targetPort));
			sender.send(new DatagramPacket(corruptFpBytes, corruptFpBytes.length, loopback, targetPort));
			sender.send(new DatagramPacket(validBytes, validBytes.length, loopback, targetPort));

			MessageHeader received = StunSocketReceiver.receiveMatching(receiver, req, 500);
			assertEquals(MessageHeaderType.BindingResponse, received.getType());
			assertTrue(received.equalTransactionID(req));
		}
	}

	@Test
	public void testEnforcesAbsoluteDeadlineUnderContinuousStrayTraffic() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");

		MessageHeader req = new MessageHeader(MessageHeaderType.BindingRequest);
		req.generateTransactionID();

		MessageHeader wrongTxResp = new MessageHeader(MessageHeaderType.BindingResponse);
		wrongTxResp.generateTransactionID();
		byte[] strayBytes = wrongTxResp.getBytesWithFingerprint();

		AtomicBoolean running = new AtomicBoolean(true);
		try (DatagramSocket receiver = new DatagramSocket(0, loopback);
				DatagramSocket flooder = new DatagramSocket(0, loopback)) {
			int targetPort = receiver.getLocalPort();
			Thread floodThread = new Thread(() -> {
				while (running.get()) {
					try {
						flooder.send(new DatagramPacket(strayBytes, strayBytes.length, loopback, targetPort));
						Thread.sleep(15);
					} catch (Exception ignored) {
						break;
					}
				}
			}, "StrayPacketSender");
			floodThread.setDaemon(true);
			floodThread.start();

			long startMs = System.currentTimeMillis();
			assertThrows(SocketTimeoutException.class,
					() -> StunSocketReceiver.receiveMatching(receiver, req, 150));
			long elapsedMs = System.currentTimeMillis() - startMs;
			assertTrue(elapsedMs < 1500, "Receive loop should respect absolute deadline, elapsed=" + elapsedMs + "ms");
		} finally {
			running.set(false);
		}
	}
}
