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

package de.javawi.jstun.header;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.attribute.Fingerprint;
import de.javawi.jstun.attribute.MessageAttribute;
import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeInterface;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.attribute.MessageIntegrity;
import de.javawi.jstun.attribute.XorMappedAddress;
import de.javawi.jstun.util.Utility;
import de.javawi.jstun.util.UtilityException;

public class MessageHeader implements MessageHeaderInterface {
	/*
	 *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |      STUN Message Type        |         Message Length        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                         Magic Cookie                          |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * |                     Transaction ID (96 bits)                  |
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(MessageHeader.class);
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();
	MessageHeaderType type;
	byte[] id = new byte[16];
	
	List<MessageAttribute> ma = new ArrayList<MessageAttribute>();
	
	public MessageHeader() {
		super();
	}
	
	public MessageHeader(MessageHeaderType type) {
		super();
		setType(type);
	}
		
    public void setType(MessageHeaderType type) {
		this.type = type;
    }
    
    public MessageHeaderType getType() {
    	return type;
    }
	
	public static int typeToInteger(MessageHeaderType type) {
		if (type == MessageHeaderType.BindingRequest) return BINDINGREQUEST;
		if (type == MessageHeaderType.BindingIndication) return BINDINGINDICATION;
		if (type == MessageHeaderType.BindingResponse) return BINDINGRESPONSE;
		if (type == MessageHeaderType.BindingErrorResponse) return BINDINGERRORRESPONSE;
		if (type == MessageHeaderType.SharedSecretRequest) return SHAREDSECRETREQUEST;
		if (type == MessageHeaderType.SharedSecretResponse) return SHAREDSECRETRESPONSE;
		if (type == MessageHeaderType.SharedSecretErrorResponse) return SHAREDSECRETERRORRESPONSE;
		if (type == MessageHeaderType.AllocateRequest) return ALLOCATEREQUEST;
		if (type == MessageHeaderType.AllocateResponse) return ALLOCATERESPONSE;
		if (type == MessageHeaderType.AllocateErrorResponse) return ALLOCATEERRORRESPONSE;
		if (type == MessageHeaderType.RefreshRequest) return REFRESHREQUEST;
		if (type == MessageHeaderType.RefreshResponse) return REFRESHRESPONSE;
		if (type == MessageHeaderType.RefreshErrorResponse) return REFRESHERRORRESPONSE;
		if (type == MessageHeaderType.SendIndication) return SENDINDICATION;
		if (type == MessageHeaderType.DataIndication) return DATAINDICATION;
		if (type == MessageHeaderType.CreatePermissionRequest) return CREATEPERMISSIONREQUEST;
		if (type == MessageHeaderType.CreatePermissionResponse) return CREATEPERMISSIONRESPONSE;
		if (type == MessageHeaderType.CreatePermissionErrorResponse) return CREATEPERMISSIONERRORRESPONSE;
		if (type == MessageHeaderType.ChannelBindRequest) return CHANNELBINDREQUEST;
		if (type == MessageHeaderType.ChannelBindResponse) return CHANNELBINDRESPONSE;
		if (type == MessageHeaderType.ChannelBindErrorResponse) return CHANNELBINDERRORRESPONSE;
		return -1;
	}
	
	public void setTransactionID(byte[] id) {
		System.arraycopy(id, 0, this.id, 0, 16);
	}
	
	public void generateTransactionID() throws UtilityException {
		id[0] = 0x21;
		id[1] = 0x12;
		id[2] = (byte) 0xA4;
		id[3] = 0x42;
		byte[] randomBytes = new byte[12];
		SECURE_RANDOM.nextBytes(randomBytes);
		System.arraycopy(randomBytes, 0, id, 4, 12);
	}

	public void generateRFC3489TransactionID() throws UtilityException {
		SECURE_RANDOM.nextBytes(id);
	}

	public boolean hasMagicCookie() {
		return (id[0] == 0x21) && (id[1] == 0x12) && (id[2] == (byte) 0xA4) && (id[3] == 0x42);
	}
	
	public byte[] getTransactionID() {
		byte[] idCopy = new byte[id.length];
		System.arraycopy(id, 0, idCopy, 0, id.length);
		return idCopy;
	}
	
	public boolean equalTransactionID(MessageHeader header) {
		byte[] idHeader = header.getTransactionID();
		if (idHeader.length != 16) return false;
		if ((idHeader[0] == id[0]) && (idHeader[1] == id[1]) && (idHeader[2] == id[2]) && (idHeader[3] == id[3]) && 
			(idHeader[4] == id[4]) && (idHeader[5] == id[5]) && (idHeader[6] == id[6]) && (idHeader[7] == id[7]) && 
			(idHeader[8] == id[8]) && (idHeader[9] == id[9]) && (idHeader[10] == id[10]) && (idHeader[11] == id[11]) &&
			(idHeader[12] == id[12]) && (idHeader[13] == id[13]) && (idHeader[14] == id[14]) && (idHeader[15] == id[15])) {
			return true;
		} else {
			return false;
		}
	}
	
	public void addMessageAttribute(MessageAttribute attri) {
		if (attri instanceof XorMappedAddress) {
			((XorMappedAddress) attri).setTransactionID(this.id);
		}
		ma.add(attri);
	}
	
	public MessageAttribute getMessageAttribute(MessageAttribute.MessageAttributeType type) {
		for (MessageAttribute attri : ma) {
			if (attri.getType() == type) {
				return attri;
			}
		}
		return null;
	}

	/**
	 * Returns all attributes of the given type in insertion/wire order
	 * (e.g. multiple {@code XOR-PEER-ADDRESS} attributes in RFC 5766 {@code CreatePermission}).
	 */
	public List<MessageAttribute> getMessageAttributes(MessageAttribute.MessageAttributeType type) {
		List<MessageAttribute> matches = new ArrayList<MessageAttribute>();
		for (MessageAttribute attri : ma) {
			if (attri.getType() == type) {
				matches.add(attri);
			}
		}
		return Collections.unmodifiableList(matches);
	}

	public List<MessageAttribute> removeMessageAttributes(MessageAttribute.MessageAttributeType type) {
		List<MessageAttribute> removed = new ArrayList<MessageAttribute>();
		ma.removeIf(attri -> {
			if (attri.getType() == type) {
				removed.add(attri);
				return true;
			}
			return false;
		});
		return removed;
	}
	
	public byte[] getBytes() throws UtilityException {
		int length = 20;
		for (MessageAttribute attri : ma) {
			if (attri instanceof XorMappedAddress) {
				((XorMappedAddress) attri).setTransactionID(this.id);
			}
			length += attri.getLength();
		}
		// add attribute size + attributes.getSize();
		byte[] result = new byte[length];
		System.arraycopy(Utility.integerToTwoBytes(typeToInteger(type)), 0, result, 0, 2);
		System.arraycopy(Utility.integerToTwoBytes(length-20), 0, result, 2, 2);
		System.arraycopy(id, 0, result, 4, 16);
		
		// arraycopy of attributes in insertion order
		int offset = 20;
		for (MessageAttribute attri : ma) {
			byte[] attrBytes = attri.getBytes();
			System.arraycopy(attrBytes, 0, result, offset, attrBytes.length);
			offset += attrBytes.length;
		}
		return result;
	}
	
	public int getLength() throws UtilityException {
		return getBytes().length;
	}

	/**
	 * Serializes this STUN/TURN message and appends an RFC 5389 §15.5 FINGERPRINT
	 * attribute as the final attribute in the message.
	 */
	public byte[] getBytesWithFingerprint() throws UtilityException {
		List<MessageAttribute> existingFp = removeMessageAttributes(MessageAttribute.MessageAttributeType.Fingerprint);
		try {
			byte[] prefix = getBytes();
			return appendFingerprint(prefix);
		} finally {
			ma.addAll(existingFp);
		}
	}

	/**
	 * Serializes this STUN/TURN message with a trailing RFC 5389 §15.4 long-term
	 * {@code MESSAGE-INTEGRITY} attribute placed after all other attributes.
	 */
	public byte[] getBytesWithLongTermMessageIntegrity(String username, String realm, String password)
			throws UtilityException {
		return serializeWithIntegrity(username, realm, password, false);
	}

	/**
	 * Serializes this STUN/TURN message with a trailing long-term {@code MESSAGE-INTEGRITY}
	 * followed by {@code FINGERPRINT} as the final attribute.
	 */
	public byte[] getBytesWithLongTermMessageIntegrityAndFingerprint(String username, String realm, String password)
			throws UtilityException {
		return serializeWithIntegrity(username, realm, password, true);
	}

	private byte[] serializeWithIntegrity(String username, String realm, String password, boolean withFingerprint)
			throws UtilityException {
		List<MessageAttribute> existingMi = removeMessageAttributes(MessageAttribute.MessageAttributeType.MessageIntegrity);
		List<MessageAttribute> existingFp = removeMessageAttributes(MessageAttribute.MessageAttributeType.Fingerprint);
		try {
			byte[] prefix = getBytes();
			byte[] hmac = MessageIntegrity.computeLongTermHMAC(prefix, username, realm, password);
			byte[] miBytes;
			try {
				miBytes = new MessageIntegrity(hmac).getBytes();
			} catch (MessageAttributeException e) {
				throw new UtilityException("Failed to serialize MESSAGE-INTEGRITY: " + e.getMessage());
			}
			byte[] withMi = new byte[prefix.length + miBytes.length];
			System.arraycopy(prefix, 0, withMi, 0, prefix.length);
			System.arraycopy(miBytes, 0, withMi, prefix.length, miBytes.length);
			byte[] miTotalLen = Utility.integerToTwoBytes(withMi.length - 20);
			withMi[2] = miTotalLen[0];
			withMi[3] = miTotalLen[1];
			return withFingerprint ? appendFingerprint(withMi) : withMi;
		} finally {
			ma.addAll(existingMi);
			ma.addAll(existingFp);
		}
	}

	private static byte[] appendFingerprint(byte[] prefix) throws UtilityException {
		long crc = Fingerprint.calculateFingerprint(prefix);
		byte[] fpBytes = new Fingerprint(crc).getBytes();

		byte[] result = new byte[prefix.length + fpBytes.length];
		System.arraycopy(prefix, 0, result, 0, prefix.length);
		System.arraycopy(fpBytes, 0, result, prefix.length, fpBytes.length);

		byte[] totalAttrLen = Utility.integerToTwoBytes(result.length - 20);
		result[2] = totalAttrLen[0];
		result[3] = totalAttrLen[1];
		return result;
	}

	/**
	 * Verifies the RFC 5389 §15.4 long-term {@code MESSAGE-INTEGRITY} attribute on a raw
	 * STUN/TURN wire packet (even when followed by {@code FINGERPRINT}).
	 */
	public static boolean verifyLongTermMessageIntegrity(byte[] fullPacket, String username, String realm, String password)
			throws UtilityException, MessageAttributeParsingException {
		int miOffset = findAttributeOffset(fullPacket, MessageAttributeInterface.MESSAGEINTEGRITY);
		if (miOffset < 0) {
			return false;
		}
		int attrLen = ((fullPacket[miOffset + 2] & 0xFF) << 8) | (fullPacket[miOffset + 3] & 0xFF);
		if (attrLen != 20 || miOffset + 24 > fullPacket.length) {
			return false;
		}
		byte[] prefix = Arrays.copyOf(fullPacket, miOffset);
		byte[] hmacBytes = Arrays.copyOfRange(fullPacket, miOffset + 4, miOffset + 24);
		MessageIntegrity mi = MessageIntegrity.parse(hmacBytes);
		return mi.verifyLongTerm(prefix, username, realm, password);
	}

	/**
	 * Verifies the RFC 5389 §15.4 short-term {@code MESSAGE-INTEGRITY} attribute on a raw
	 * STUN/TURN wire packet (even when followed by {@code FINGERPRINT}).
	 */
	public static boolean verifyShortTermMessageIntegrity(byte[] fullPacket, String password)
			throws UtilityException, MessageAttributeParsingException {
		int miOffset = findAttributeOffset(fullPacket, MessageAttributeInterface.MESSAGEINTEGRITY);
		if (miOffset < 0) {
			return false;
		}
		int attrLen = ((fullPacket[miOffset + 2] & 0xFF) << 8) | (fullPacket[miOffset + 3] & 0xFF);
		if (attrLen != 20 || miOffset + 24 > fullPacket.length) {
			return false;
		}
		byte[] prefix = Arrays.copyOf(fullPacket, miOffset);
		byte[] hmacBytes = Arrays.copyOfRange(fullPacket, miOffset + 4, miOffset + 24);
		MessageIntegrity mi = MessageIntegrity.parse(hmacBytes);
		return mi.verifyShortTerm(prefix, password);
	}

	private static int findAttributeOffset(byte[] packet, int targetAttrType) {
		if (packet == null || packet.length < 20) {
			return -1;
		}
		int payloadLen = ((packet[2] & 0xFF) << 8) | (packet[3] & 0xFF);
		int end = Math.min(packet.length, 20 + payloadLen);
		int offset = 20;
		while (offset + 4 <= end) {
			int attrType = ((packet[offset] & 0xFF) << 8) | (packet[offset + 1] & 0xFF);
			int attrLen = ((packet[offset + 2] & 0xFF) << 8) | (packet[offset + 3] & 0xFF);
			if (attrType == targetAttrType) {
				return offset;
			}
			int padded = (attrLen + 3) & ~3;
			int step = 4 + padded;
			if (offset + step > end) {
				step = 4 + attrLen;
			}
			if (step <= 0) {
				return -1;
			}
			offset += step;
		}
		return -1;
	}
	
	public void parseAttributes(byte[] data) throws MessageAttributeParsingException {
		try {
			if (data.length < 20) {
				throw new MessageAttributeParsingException(
						"Data array too short: expected at least 20 bytes, actual " + data.length + " bytes");
			}
			byte[] lengthArray = new byte[2];
			System.arraycopy(data, 2, lengthArray, 0, 2);
			int length = Utility.twoBytesToInteger(lengthArray);
			System.arraycopy(data, 4, id, 0, 16);
			LOGGER.debug("Parsing message attributes (payload length: {} bytes, magic cookie: {}).", length, hasMagicCookie());
			byte[] cuttedData;
			int offset = 20;
			while (length > 0) {
				if (length < 4 || (offset + length) > data.length) {
					throw new MessageAttributeParsingException(
							"Data array too short: expected " + (offset + length) + " bytes, actual " + data.length
									+ " bytes (remaining payload length=" + length + ")");
				}
				cuttedData = new byte[length];
				System.arraycopy(data, offset, cuttedData, 0, length);
				byte[] attrLenArray = new byte[2];
				System.arraycopy(cuttedData, 2, attrLenArray, 0, 2);
				int attrValueLength = Utility.twoBytesToInteger(attrLenArray);
				int paddedValueLength = attrValueLength;
				if ((paddedValueLength % 4) != 0) {
					paddedValueLength += 4 - (paddedValueLength % 4);
				}
				int wireAttrLength = 4 + paddedValueLength;
				if (wireAttrLength > length) {
					wireAttrLength = 4 + attrValueLength;
				}
				MessageAttribute parsedAttr = MessageAttribute.parseCommonHeader(cuttedData, id);
				addMessageAttribute(parsedAttr);
				length -= wireAttrLength;
				offset += wireAttrLength;
			}
		} catch (UtilityException ue) {
			throw new MessageAttributeParsingException("Parsing error");
		}
	}
	
	public static MessageHeader parseHeader(byte[] data) throws MessageHeaderParsingException {
		try {
			if (data == null || data.length < 2) {
				throw new MessageHeaderParsingException("Data array too short");
			}
			MessageHeader mh = new MessageHeader();
			byte[] typeArray = new byte[2];
			System.arraycopy(data, 0, typeArray, 0, 2);
			int type = Utility.twoBytesToInteger(typeArray);
			switch (type) {
				case BINDINGREQUEST: mh.setType(MessageHeaderType.BindingRequest); LOGGER.debug("Binding Request received."); break;
				case BINDINGINDICATION: mh.setType(MessageHeaderType.BindingIndication); LOGGER.debug("Binding Indication received."); break;
				case BINDINGRESPONSE: mh.setType(MessageHeaderType.BindingResponse); LOGGER.debug("Binding Response received."); break;
				case BINDINGERRORRESPONSE: mh.setType(MessageHeaderType.BindingErrorResponse); LOGGER.debug("Binding Error Response received."); break;
				case SHAREDSECRETREQUEST: mh.setType(MessageHeaderType.SharedSecretRequest); LOGGER.debug("Shared Secret Request received."); break;
				case SHAREDSECRETRESPONSE: mh.setType(MessageHeaderType.SharedSecretResponse); LOGGER.debug("Shared Secret Response received."); break;
				case SHAREDSECRETERRORRESPONSE: mh.setType(MessageHeaderType.SharedSecretErrorResponse); LOGGER.debug("Shared Secret Error Response received."); break;
				case ALLOCATEREQUEST: mh.setType(MessageHeaderType.AllocateRequest); LOGGER.debug("Allocate Request received."); break;
				case ALLOCATERESPONSE: mh.setType(MessageHeaderType.AllocateResponse); LOGGER.debug("Allocate Response received."); break;
				case ALLOCATEERRORRESPONSE: mh.setType(MessageHeaderType.AllocateErrorResponse); LOGGER.debug("Allocate Error Response received."); break;
				case REFRESHREQUEST: mh.setType(MessageHeaderType.RefreshRequest); LOGGER.debug("Refresh Request received."); break;
				case REFRESHRESPONSE: mh.setType(MessageHeaderType.RefreshResponse); LOGGER.debug("Refresh Response received."); break;
				case REFRESHERRORRESPONSE: mh.setType(MessageHeaderType.RefreshErrorResponse); LOGGER.debug("Refresh Error Response received."); break;
				case SENDINDICATION: mh.setType(MessageHeaderType.SendIndication); LOGGER.debug("Send Indication received."); break;
				case DATAINDICATION: mh.setType(MessageHeaderType.DataIndication); LOGGER.debug("Data Indication received."); break;
				case CREATEPERMISSIONREQUEST: mh.setType(MessageHeaderType.CreatePermissionRequest); LOGGER.debug("CreatePermission Request received."); break;
				case CREATEPERMISSIONRESPONSE: mh.setType(MessageHeaderType.CreatePermissionResponse); LOGGER.debug("CreatePermission Response received."); break;
				case CREATEPERMISSIONERRORRESPONSE: mh.setType(MessageHeaderType.CreatePermissionErrorResponse); LOGGER.debug("CreatePermission Error Response received."); break;
				case CHANNELBINDREQUEST: mh.setType(MessageHeaderType.ChannelBindRequest); LOGGER.debug("ChannelBind Request received."); break;
				case CHANNELBINDRESPONSE: mh.setType(MessageHeaderType.ChannelBindResponse); LOGGER.debug("ChannelBind Response received."); break;
				case CHANNELBINDERRORRESPONSE: mh.setType(MessageHeaderType.ChannelBindErrorResponse); LOGGER.debug("ChannelBind Error Response received."); break;
				default: throw new MessageHeaderParsingException("Message type " + type + "is not supported"); 
			}
			return mh;
		} catch (UtilityException ue) {
			throw new MessageHeaderParsingException("Parsing error");
		}
	}
}
