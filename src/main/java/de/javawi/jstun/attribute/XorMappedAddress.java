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

package de.javawi.jstun.attribute;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.util.Address;
import de.javawi.jstun.util.Utility;
import de.javawi.jstun.util.UtilityException;

public class XorMappedAddress extends MappedResponseChangedSourceAddressReflectedFrom {
	private static final Logger LOGGER = LoggerFactory.getLogger(XorMappedAddress.class);
	private static final byte[] MAGIC_COOKIE_BYTES = new byte[] { 0x21, 0x12, (byte) 0xA4, 0x42 };
	private byte[] transactionId = new byte[12];

	public XorMappedAddress() {
		super(MessageAttribute.MessageAttributeType.XorMappedAddress);
	}

	public XorMappedAddress(byte[] transactionId) {
		super(MessageAttribute.MessageAttributeType.XorMappedAddress);
		setTransactionID(transactionId);
	}

	public void setTransactionID(byte[] transactionId) {
		if (transactionId == null) {
			return;
		}
		if (transactionId.length == 12) {
			System.arraycopy(transactionId, 0, this.transactionId, 0, 12);
		} else if (transactionId.length >= 16) {
			System.arraycopy(transactionId, 4, this.transactionId, 0, 12);
		}
	}

	public byte[] getTransactionID() {
		byte[] copy = new byte[12];
		System.arraycopy(this.transactionId, 0, copy, 0, 12);
		return copy;
	}

	private static byte[] buildXorMask(byte[] transactionId) {
		byte[] mask = new byte[16];
		System.arraycopy(MAGIC_COOKIE_BYTES, 0, mask, 0, 4);
		if (transactionId != null) {
			if (transactionId.length == 12) {
				System.arraycopy(transactionId, 0, mask, 4, 12);
			} else if (transactionId.length >= 16) {
				System.arraycopy(transactionId, 4, mask, 4, 12);
			}
		}
		return mask;
	}

	@Override
	public byte[] getBytes() throws UtilityException {
		return getBytes(this.transactionId);
	}

	public byte[] getBytes(byte[] transactionId) throws UtilityException {
		byte[] addressInBytes = address.getBytes();
		int valueLength = 4 + addressInBytes.length;
		byte[] result = new byte[4 + valueLength];

		// attribute header
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(valueLength), 0, result, 2, 2);

		// family
		result[4] = 0x00;
		if (addressInBytes.length == 4) {
			result[5] = Utility.integerToOneByte(0x01);
		} else {
			result[5] = Utility.integerToOneByte(0x02);
		}

		// X-Port (port XOR high 16-bits of magic cookie 0x2112)
		int xPort = (port ^ 0x2112) & 0xFFFF;
		System.arraycopy(Utility.integerToTwoBytes(xPort), 0, result, 6, 2);

		// X-Address
		byte[] mask = buildXorMask(transactionId);
		for (int i = 0; i < addressInBytes.length; i++) {
			result[8 + i] = (byte) (addressInBytes[i] ^ mask[i]);
		}
		return result;
	}

	public static MessageAttribute parse(byte[] data) throws MessageAttributeParsingException {
		return parse(data, null);
	}

	public static MessageAttribute parse(byte[] data, byte[] transactionId) throws MessageAttributeParsingException {
		try {
			if (data.length < 8) {
				throw new MessageAttributeParsingException("Data array too short");
			}
			int family = Utility.oneByteToInteger(data[1]);
			if (family != 0x01 && family != 0x02) {
				throw new MessageAttributeParsingException("Family " + family + " is not supported");
			}
			int addrLen = (family == 0x01) ? 4 : 16;
			if (data.length < 4 + addrLen) {
				throw new MessageAttributeParsingException("Data array too short for family " + family);
			}

			byte[] portArray = new byte[2];
			System.arraycopy(data, 2, portArray, 0, 2);
			int xPort = Utility.twoBytesToInteger(portArray);
			int decodedPort = (xPort ^ 0x2112) & 0xFFFF;

			byte[] mask = buildXorMask(transactionId);
			int[] octets = new int[addrLen];
			for (int i = 0; i < addrLen; i++) {
				byte decodedByte = (byte) (data[4 + i] ^ mask[i]);
				octets[i] = Utility.oneByteToInteger(decodedByte);
			}

			XorMappedAddress xma = new XorMappedAddress(transactionId);
			xma.setPort(decodedPort);
			xma.setAddress(new Address(octets));
			LOGGER.debug("Message Attribute: XOR-Mapped Address parsed: " + xma.toString() + ".");
			return xma;
		} catch (UtilityException ue) {
			throw new MessageAttributeParsingException("Parsing error");
		} catch (MessageAttributeException mae) {
			throw new MessageAttributeParsingException("Port parsing error");
		}
	}
}
