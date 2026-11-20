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

import java.util.Arrays;

import de.javawi.jstun.attribute.ChannelNumber;
import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeParsingException;

/**
 * RFC 5766 §11 {@code ChannelData} binary framing:
 * <pre>
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Channel Number        |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * /                       Application Data                        /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 */
public final class ChannelData {
	public static final int HEADER_LENGTH = 4;
	public static final int MAX_DATA_LENGTH = 65535;

	private final int channelNumber;
	private final byte[] data;

	public ChannelData(int channelNumber, byte[] data) throws MessageAttributeException {
		if (channelNumber < ChannelNumber.MIN_CHANNEL_NUMBER || channelNumber > ChannelNumber.MAX_CHANNEL_NUMBER) {
			throw new MessageAttributeException(
					"ChannelData channel number out of range (0x4000..0x7FFF): 0x" + Integer.toHexString(channelNumber));
		}
		if (data != null && data.length > MAX_DATA_LENGTH) {
			throw new MessageAttributeException("ChannelData payload exceeds 65535 bytes: " + data.length);
		}
		this.channelNumber = channelNumber;
		this.data = (data != null) ? Arrays.copyOf(data, data.length) : new byte[0];
	}

	/**
	 * Returns {@code true} if the packet's top two bits are {@code 01} (RFC 5766 §11.4),
	 * indicating a {@code ChannelData} frame rather than a STUN/TURN message ({@code 00}).
	 */
	public static boolean isChannelData(byte[] packet) {
		return packet != null && packet.length >= HEADER_LENGTH && ((packet[0] & 0xC0) == 0x40);
	}

	public int getChannelNumber() {
		return channelNumber;
	}

	public byte[] getData() {
		return Arrays.copyOf(data, data.length);
	}

	public int getLength() {
		return data.length;
	}

	/**
	 * Encodes this {@code ChannelData} frame for UDP transport (no trailing padding per RFC 5766 §11.5).
	 */
	public byte[] getBytes() {
		return encode(false);
	}

	/**
	 * Encodes this {@code ChannelData} frame padded to a 4-byte boundary (for TCP/TLS stream framing per RFC 5766 §11.5).
	 */
	public byte[] getBytesPadded() {
		return encode(true);
	}

	private byte[] encode(boolean padToFourBytes) {
		int totalLen = HEADER_LENGTH + data.length;
		if (padToFourBytes && (totalLen % 4) != 0) {
			totalLen += 4 - (totalLen % 4);
		}
		byte[] out = new byte[totalLen];
		out[0] = (byte) ((channelNumber >>> 8) & 0xFF);
		out[1] = (byte) (channelNumber & 0xFF);
		out[2] = (byte) ((data.length >>> 8) & 0xFF);
		out[3] = (byte) (data.length & 0xFF);
		System.arraycopy(data, 0, out, HEADER_LENGTH, data.length);
		return out;
	}

	public static ChannelData parse(byte[] packet) throws MessageAttributeParsingException {
		if (packet == null || packet.length < HEADER_LENGTH) {
			throw new MessageAttributeParsingException("ChannelData packet too short");
		}
		int ch = ((packet[0] & 0xFF) << 8) | (packet[1] & 0xFF);
		if (ch < ChannelNumber.MIN_CHANNEL_NUMBER || ch > ChannelNumber.MAX_CHANNEL_NUMBER) {
			throw new MessageAttributeParsingException("Invalid ChannelData channel number: 0x" + Integer.toHexString(ch));
		}
		int len = ((packet[2] & 0xFF) << 8) | (packet[3] & 0xFF);
		if (HEADER_LENGTH + len > packet.length) {
			throw new MessageAttributeParsingException(
					"ChannelData truncated: declared length=" + len + ", available=" + (packet.length - HEADER_LENGTH));
		}
		byte[] payload = Arrays.copyOfRange(packet, HEADER_LENGTH, HEADER_LENGTH + len);
		try {
			return new ChannelData(ch, payload);
		} catch (MessageAttributeException e) {
			throw new MessageAttributeParsingException("Invalid ChannelData: " + e.getMessage());
		}
	}
}
