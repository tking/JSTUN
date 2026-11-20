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

package de.javawi.jstun.turn;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.attribute.ChannelNumber;
import de.javawi.jstun.attribute.Data;
import de.javawi.jstun.attribute.DontFragment;
import de.javawi.jstun.attribute.ErrorCode;
import de.javawi.jstun.attribute.EvenPort;
import de.javawi.jstun.attribute.Fingerprint;
import de.javawi.jstun.attribute.Lifetime;
import de.javawi.jstun.attribute.MessageAttribute;
import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.attribute.MessageIntegrity;
import de.javawi.jstun.attribute.Nonce;
import de.javawi.jstun.attribute.Realm;
import de.javawi.jstun.attribute.RequestedTransport;
import de.javawi.jstun.attribute.ReservationToken;
import de.javawi.jstun.attribute.Software;
import de.javawi.jstun.attribute.Username;
import de.javawi.jstun.attribute.XorPeerAddress;
import de.javawi.jstun.attribute.XorRelayedAddress;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.util.Address;

/**
 * Unit tests for RFC 5766 (TURN) wire protocol extensions: message types,
 * attributes, repeated attributes, ordered {@code MESSAGE-INTEGRITY} + {@code FINGERPRINT},
 * TURN error codes, and {@link ChannelData} framing.
 */
public class Rfc5766WireProtocolTest {

	@Test
	public void testAllTurnMessageHeaderTypesRoundTrip() throws Exception {
		MessageHeaderType[] turnTypes = new MessageHeaderType[] {
			MessageHeaderType.AllocateRequest,
			MessageHeaderType.AllocateResponse,
			MessageHeaderType.AllocateErrorResponse,
			MessageHeaderType.RefreshRequest,
			MessageHeaderType.RefreshResponse,
			MessageHeaderType.RefreshErrorResponse,
			MessageHeaderType.SendIndication,
			MessageHeaderType.DataIndication,
			MessageHeaderType.CreatePermissionRequest,
			MessageHeaderType.CreatePermissionResponse,
			MessageHeaderType.CreatePermissionErrorResponse,
			MessageHeaderType.ChannelBindRequest,
			MessageHeaderType.ChannelBindResponse,
			MessageHeaderType.ChannelBindErrorResponse
		};
		for (MessageHeaderType t : turnTypes) {
			MessageHeader mh = new MessageHeader(t);
			mh.generateTransactionID();
			byte[] raw = mh.getBytes();
			MessageHeader parsed = MessageHeader.parseHeader(raw);
			assertEquals(t, parsed.getType());
		}
	}

	@Test
	public void testAllTurnAttributesRoundTripAndValidation() throws Exception {
		// ChannelNumber
		ChannelNumber chMin = new ChannelNumber(ChannelNumber.MIN_CHANNEL_NUMBER);
		ChannelNumber chMax = new ChannelNumber(ChannelNumber.MAX_CHANNEL_NUMBER);
		assertEquals(0x4000, chMin.getChannelNumber());
		assertEquals(0x7FFF, chMax.getChannelNumber());
		assertEquals(8, chMin.getBytes().length);
		assertThrows(MessageAttributeException.class, () -> new ChannelNumber(0x3FFF));
		assertThrows(MessageAttributeException.class, () -> new ChannelNumber(0x8000));
		assertThrows(MessageAttributeParsingException.class, () -> ChannelNumber.parse(new byte[2]));

		// Lifetime
		Lifetime lt = new Lifetime(3600L);
		assertEquals(3600L, lt.getLifetime());
		assertEquals(8, lt.getBytes().length);
		Lifetime maxLt = new Lifetime(0xFFFFFFFFL);
		assertEquals(0xFFFFFFFFL, maxLt.getLifetime());
		assertThrows(MessageAttributeException.class, () -> new Lifetime(-1L));
		assertThrows(MessageAttributeException.class, () -> new Lifetime(0x1_0000_0000L));
		assertThrows(MessageAttributeParsingException.class, () -> Lifetime.parse(new byte[3]));

		// Data (including binary payload ending with 0x00 and non-4-byte length)
		byte[] binaryPayload = new byte[] { 0x01, 0x02, 0x03, 0x00, 0x00 };
		Data dataAttr = new Data(binaryPayload);
		byte[] copy = dataAttr.getData();
		assertArrayEquals(binaryPayload, copy);
		copy[0] = 0x7F;
		assertEquals(0x01, dataAttr.getData()[0]); // defensive copy
		assertEquals(12, dataAttr.getBytes().length); // 4 header + 5 padded to 8
		assertArrayEquals(binaryPayload, Data.parse(binaryPayload).getData());
		assertEquals(0, new Data(null).getData().length);

		// EvenPort
		EvenPort epTrue = new EvenPort(true);
		EvenPort epFalse = new EvenPort(false);
		assertTrue(epTrue.isReserveNextPort());
		assertFalse(epFalse.isReserveNextPort());
		assertEquals(8, epTrue.getBytes().length);
		assertEquals((byte) 0x80, epTrue.getBytes()[4]);
		assertEquals((byte) 0x00, epFalse.getBytes()[4]);
		assertThrows(MessageAttributeParsingException.class, () -> EvenPort.parse(new byte[2]));

		// RequestedTransport
		RequestedTransport rt = new RequestedTransport(RequestedTransport.PROTOCOL_UDP);
		assertEquals(17, rt.getProtocol());
		assertEquals(8, rt.getBytes().length);
		assertThrows(MessageAttributeException.class, () -> new RequestedTransport(-1));
		assertThrows(MessageAttributeException.class, () -> new RequestedTransport(256));
		assertThrows(MessageAttributeParsingException.class, () -> RequestedTransport.parse(new byte[2]));

		// DontFragment
		DontFragment df = new DontFragment();
		assertEquals(4, df.getBytes().length);
		assertNotNull(DontFragment.parse(new byte[0]));
		assertThrows(MessageAttributeParsingException.class, () -> DontFragment.parse(new byte[1]));

		// ReservationToken
		byte[] tokBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
		ReservationToken tok1 = new ReservationToken(tokBytes);
		ReservationToken tok2 = new ReservationToken(tokBytes);
		assertEquals(tok1, tok2);
		assertEquals(tok1.hashCode(), tok2.hashCode());
		assertNotEquals(tok1, new ReservationToken(new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 }));
		assertEquals(12, tok1.getBytes().length);
		assertThrows(MessageAttributeException.class, () -> new ReservationToken(new byte[7]));
		assertThrows(MessageAttributeException.class, () -> new ReservationToken(null));
		assertThrows(MessageAttributeParsingException.class, () -> ReservationToken.parse(new byte[4]));

		// Full MessageHeader round-trip containing all TURN attributes
		MessageHeader mh = new MessageHeader(MessageHeaderType.AllocateResponse);
		mh.generateTransactionID();
		mh.addMessageAttribute(chMax);
		mh.addMessageAttribute(lt);
		mh.addMessageAttribute(dataAttr);
		mh.addMessageAttribute(epTrue);
		mh.addMessageAttribute(rt);
		mh.addMessageAttribute(df);
		mh.addMessageAttribute(tok1);

		XorPeerAddress peerV4 = new XorPeerAddress();
		peerV4.setAddress(new Address("198.51.100.10"));
		peerV4.setPort(40001);
		mh.addMessageAttribute(peerV4);

		XorRelayedAddress relayV6 = new XorRelayedAddress();
		relayV6.setAddress(new Address("2001:db8::42"));
		relayV6.setPort(50000);
		mh.addMessageAttribute(relayV6);

		byte[] wire = mh.getBytesWithFingerprint();
		assertTrue(Fingerprint.verify(wire));

		MessageHeader parsed = MessageHeader.parseHeader(wire);
		parsed.parseAttributes(wire);
		assertEquals(0x7FFF, ((ChannelNumber) parsed.getMessageAttribute(MessageAttributeType.ChannelNumber)).getChannelNumber());
		assertEquals(3600L, ((Lifetime) parsed.getMessageAttribute(MessageAttributeType.Lifetime)).getLifetime());
		assertArrayEquals(binaryPayload, ((Data) parsed.getMessageAttribute(MessageAttributeType.Data)).getData());
		assertTrue(((EvenPort) parsed.getMessageAttribute(MessageAttributeType.EvenPort)).isReserveNextPort());
		assertEquals(17, ((RequestedTransport) parsed.getMessageAttribute(MessageAttributeType.RequestedTransport)).getProtocol());
		assertNotNull(parsed.getMessageAttribute(MessageAttributeType.DontFragment));
		assertEquals(tok1, parsed.getMessageAttribute(MessageAttributeType.ReservationToken));

		XorPeerAddress parsedPeer = (XorPeerAddress) parsed.getMessageAttribute(MessageAttributeType.XorPeerAddress);
		assertEquals(new Address("198.51.100.10"), parsedPeer.getAddress());
		assertEquals(40001, parsedPeer.getPort());

		XorRelayedAddress parsedRelay = (XorRelayedAddress) parsed.getMessageAttribute(MessageAttributeType.XorRelayedAddress);
		assertEquals(new Address("2001:db8::42"), parsedRelay.getAddress());
		assertEquals(50000, parsedRelay.getPort());
	}

	@Test
	public void testMultipleXorPeerAddressesInCreatePermissionAndIntegrityOrdering() throws Exception {
		MessageHeader cpReq = new MessageHeader(MessageHeaderType.CreatePermissionRequest);
		cpReq.generateTransactionID();
		cpReq.addMessageAttribute(new Username("turnuser"));
		cpReq.addMessageAttribute(new Realm("example.org"));
		cpReq.addMessageAttribute(new Nonce("nonce-abc"));

		String[] peerIps = new String[] { "198.51.100.1", "198.51.100.2", "203.0.113.5" };
		for (int i = 0; i < peerIps.length; i++) {
			XorPeerAddress xpa = new XorPeerAddress();
			xpa.setAddress(new Address(peerIps[i]));
			xpa.setPort(30000 + i);
			cpReq.addMessageAttribute(xpa);
		}
		cpReq.addMessageAttribute(Software.jstun());

		byte[] wire = cpReq.getBytesWithLongTermMessageIntegrityAndFingerprint("turnuser", "example.org", "secret123");
		assertTrue(Fingerprint.verify(wire));
		assertTrue(MessageHeader.verifyLongTermMessageIntegrity(wire, "turnuser", "example.org", "secret123"));
		assertFalse(MessageHeader.verifyLongTermMessageIntegrity(wire, "turnuser", "example.org", "wrong-pass"));

		MessageHeader parsed = MessageHeader.parseHeader(wire);
		parsed.parseAttributes(wire);
		List<MessageAttribute> peers = parsed.getMessageAttributes(MessageAttributeType.XorPeerAddress);
		assertEquals(3, peers.size());
		for (int i = 0; i < peerIps.length; i++) {
			XorPeerAddress p = (XorPeerAddress) peers.get(i);
			assertEquals(new Address(peerIps[i]), p.getAddress());
			assertEquals(30000 + i, p.getPort());
		}

		// Short-term verify helper check
		MessageHeader st = new MessageHeader(MessageHeaderType.BindingRequest);
		st.generateTransactionID();
		st.addMessageAttribute(new Username("u1"));
		byte[] prefix = st.getBytes();
		byte[] hmac = MessageIntegrity.computeShortTermHMAC(prefix, "shortpass");
		st.addMessageAttribute(new MessageIntegrity(hmac));
		byte[] stWire = st.getBytesWithFingerprint();
		assertTrue(MessageHeader.verifyShortTermMessageIntegrity(stWire, "shortpass"));
		assertFalse(MessageHeader.verifyShortTermMessageIntegrity(stWire, "badpass"));
		assertFalse(MessageHeader.verifyLongTermMessageIntegrity(new byte[20], "u", "r", "p"));
	}

	@Test
	public void testRfc5766TurnErrorCodes() throws Exception {
		int[] codes = new int[] { 403, 437, 440, 441, 442, 486, 508 };
		String[] expectedReasons = new String[] {
			"Forbidden",
			"Allocation Mismatch",
			"Address Family not Supported",
			"Wrong Credentials",
			"Unsupported Transport Protocol",
			"Allocation Quota Reached",
			"Insufficient Capacity"
		};
		for (int i = 0; i < codes.length; i++) {
			ErrorCode ec = new ErrorCode();
			ec.setResponseCode(codes[i]);
			assertEquals(codes[i], ec.getResponseCode());
			assertEquals(expectedReasons[i], ec.getReason());
		}
	}

	@Test
	public void testChannelDataFramingAndDemux() throws Exception {
		byte[] payload = new byte[] { 'h', 'e', 'l', 'l', 'o' }; // 5 bytes (not multiple of 4)
		ChannelData cd = new ChannelData(0x4001, payload);
		assertEquals(0x4001, cd.getChannelNumber());
		assertEquals(5, cd.getLength());
		assertArrayEquals(payload, cd.getData());

		byte[] udpBytes = cd.getBytes();
		assertEquals(9, udpBytes.length); // 4 header + 5 payload (no padding on UDP)
		assertTrue(ChannelData.isChannelData(udpBytes));

		byte[] tcpBytes = cd.getBytesPadded();
		assertEquals(12, tcpBytes.length); // padded to 4-byte boundary
		assertTrue(ChannelData.isChannelData(tcpBytes));

		ChannelData parsedUdp = ChannelData.parse(udpBytes);
		assertEquals(0x4001, parsedUdp.getChannelNumber());
		assertArrayEquals(payload, parsedUdp.getData());

		ChannelData parsedTcp = ChannelData.parse(tcpBytes);
		assertEquals(0x4001, parsedTcp.getChannelNumber());
		assertArrayEquals(payload, parsedTcp.getData());

		// STUN packet must NOT be detected as ChannelData
		MessageHeader stun = new MessageHeader(MessageHeaderType.BindingRequest);
		stun.generateTransactionID();
		assertFalse(ChannelData.isChannelData(stun.getBytes()));
		assertFalse(ChannelData.isChannelData(null));
		assertFalse(ChannelData.isChannelData(new byte[3]));

		// Validation errors
		assertThrows(MessageAttributeException.class, () -> new ChannelData(0x3FFF, payload));
		assertThrows(MessageAttributeException.class, () -> new ChannelData(0x8000, payload));
		assertThrows(MessageAttributeException.class, () -> new ChannelData(0x4000, new byte[65536]));
		assertThrows(MessageAttributeParsingException.class, () -> ChannelData.parse(new byte[3]));
		assertThrows(MessageAttributeParsingException.class, () -> ChannelData.parse(new byte[] { 0x00, 0x01, 0x00, 0x00 }));
		assertThrows(MessageAttributeParsingException.class, () -> ChannelData.parse(new byte[] { 0x40, 0x01, 0x00, 0x10, 0x01 }));
	}
}
