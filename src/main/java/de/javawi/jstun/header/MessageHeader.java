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
import java.util.Iterator;
import java.util.TreeMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.attribute.MessageAttribute;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
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
	
	TreeMap<MessageAttribute.MessageAttributeType, MessageAttribute> ma = new TreeMap<MessageAttribute.MessageAttributeType, MessageAttribute>();
	
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
		if (type == MessageHeaderType.BindingResponse) return BINDINGRESPONSE;
		if (type == MessageHeaderType.BindingErrorResponse) return BINDINGERRORRESPONSE;
		if (type == MessageHeaderType.SharedSecretRequest) return SHAREDSECRETREQUEST;
		if (type == MessageHeaderType.SharedSecretResponse) return SHAREDSECRETRESPONSE;
		if (type == MessageHeaderType.SharedSecretErrorResponse) return SHAREDSECRETERRORRESPONSE;
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
		ma.put(attri.getType(), attri);
	}
	
	public MessageAttribute getMessageAttribute(MessageAttribute.MessageAttributeType type) {
		return ma.get(type);
	}
	
	public byte[] getBytes() throws UtilityException {
		int length = 20;
		Iterator<MessageAttribute.MessageAttributeType> it = ma.keySet().iterator();
		while (it.hasNext()) {
			MessageAttribute attri = ma.get(it.next());
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
		
		// arraycopy of attributes
		int offset = 20;
		it = ma.keySet().iterator();
		while (it.hasNext()) {
			MessageAttribute attri = ma.get(it.next());
			int attrLen = attri.getLength();
			System.arraycopy(attri.getBytes(), 0, result, offset, attrLen);
			offset += attrLen;
		}
		return result;
	}
	
	public int getLength() throws UtilityException {
		return getBytes().length;
	}
	
	public void parseAttributes(byte[] data) throws MessageAttributeParsingException {
		try {
			byte[] lengthArray = new byte[2];
			System.arraycopy(data, 2, lengthArray, 0, 2);
			int length = Utility.twoBytesToInteger(lengthArray);
			System.arraycopy(data, 4, id, 0, 16);
			byte[] cuttedData;
			int offset = 20;
			while (length > 0) {
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
			MessageHeader mh = new MessageHeader();
			byte[] typeArray = new byte[2];
			System.arraycopy(data, 0, typeArray, 0, 2);
			int type = Utility.twoBytesToInteger(typeArray);
			switch (type) {
				case BINDINGREQUEST: mh.setType(MessageHeaderType.BindingRequest); LOGGER.debug("Binding Request received."); break;
				case BINDINGRESPONSE: mh.setType(MessageHeaderType.BindingResponse); LOGGER.debug("Binding Response received."); break;
				case BINDINGERRORRESPONSE: mh.setType(MessageHeaderType.BindingErrorResponse); LOGGER.debug("Binding Error Response received."); break;
				case SHAREDSECRETREQUEST: mh.setType(MessageHeaderType.SharedSecretRequest); LOGGER.debug("Shared Secret Request received."); break;
				case SHAREDSECRETRESPONSE: mh.setType(MessageHeaderType.SharedSecretResponse); LOGGER.debug("Shared Secret Response received."); break;
				case SHAREDSECRETERRORRESPONSE: mh.setType(MessageHeaderType.SharedSecretErrorResponse); LOGGER.debug("Shared Secret Error Response received.");break;
				default: throw new MessageHeaderParsingException("Message type " + type + "is not supported"); 
			}
			return mh;
		} catch (UtilityException ue) {
			throw new MessageHeaderParsingException("Parsing error");
		}
	}
}
