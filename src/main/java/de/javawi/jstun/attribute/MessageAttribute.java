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

import de.javawi.jstun.util.Utility;
import de.javawi.jstun.util.UtilityException;


public abstract class MessageAttribute implements MessageAttributeInterface {
	private static final Logger LOGGER = LoggerFactory.getLogger(MessageAttribute.class);
	MessageAttributeType type;
	
	public MessageAttribute() {
	}
	
	public MessageAttribute(MessageAttributeType type) {
		setType(type);
	}
	
	public void setType(MessageAttributeType type) {
		this.type = type;
	}
	
	public MessageAttribute.MessageAttributeType getType() {
		return type;
	}
	
	public static int typeToInteger(MessageAttributeType type) {
		if (type == MessageAttributeType.MappedAddress) return MAPPEDADDRESS;
		if (type == MessageAttributeType.ResponseAddress) return RESPONSEADDRESS;
		if (type == MessageAttributeType.ChangeRequest) return CHANGEREQUEST;
		if (type == MessageAttributeType.SourceAddress) return SOURCEADDRESS;
		if (type == MessageAttributeType.ChangedAddress) return CHANGEDADDRESS;
		if (type == MessageAttributeType.Username) return USERNAME;
		if (type == MessageAttributeType.Password) return PASSWORD;
		if (type == MessageAttributeType.MessageIntegrity) return MESSAGEINTEGRITY;
		if (type == MessageAttributeType.ErrorCode) return ERRORCODE;
		if (type == MessageAttributeType.UnknownAttribute) return UNKNOWNATTRIBUTE;
		if (type == MessageAttributeType.ReflectedFrom) return REFLECTEDFROM;
		if (type == MessageAttributeType.ChannelNumber) return CHANNELNUMBER;
		if (type == MessageAttributeType.Lifetime) return LIFETIME;
		if (type == MessageAttributeType.XorPeerAddress) return XORPEERADDRESS;
		if (type == MessageAttributeType.Data) return DATA;
		if (type == MessageAttributeType.Realm) return REALM;
		if (type == MessageAttributeType.Nonce) return NONCE;
		if (type == MessageAttributeType.XorRelayedAddress) return XORRELAYEDADDRESS;
		if (type == MessageAttributeType.EvenPort) return EVENPORT;
		if (type == MessageAttributeType.RequestedTransport) return REQUESTEDTRANSPORT;
		if (type == MessageAttributeType.DontFragment) return DONTFRAGMENT;
		if (type == MessageAttributeType.MessageIntegritySha256) return MESSAGEINTEGRITYSHA256;
		if (type == MessageAttributeType.XorMappedAddress) return XORMAPPEDADDRESS;
		if (type == MessageAttributeType.ReservationToken) return RESERVATIONTOKEN;
		if (type == MessageAttributeType.Priority) return PRIORITY;
		if (type == MessageAttributeType.Padding) return PADDING;
		if (type == MessageAttributeType.ResponsePort) return RESPONSEPORT;
		if (type == MessageAttributeType.Software) return SOFTWARE;
		if (type == MessageAttributeType.AlternateServer) return ALTERNATESERVER;
		if (type == MessageAttributeType.Fingerprint) return FINGERPRINT;
		if (type == MessageAttributeType.Userhash) return USERHASH;
		if (type == MessageAttributeType.ResponseOrigin) return RESPONSEORIGIN;
		if (type == MessageAttributeType.OtherAddress) return OTHERADDRESS;
		if (type == MessageAttributeType.Dummy) return DUMMY;
		return -1;
	}
	
	public static MessageAttributeType intToType(long type) {
		if (type == MAPPEDADDRESS) return MessageAttributeType.MappedAddress;
		if (type == RESPONSEADDRESS) return MessageAttributeType.ResponseAddress;
		if (type == CHANGEREQUEST) return MessageAttributeType.ChangeRequest;
		if (type == SOURCEADDRESS) return MessageAttributeType.SourceAddress;
		if (type == CHANGEDADDRESS) return MessageAttributeType.ChangedAddress;
		if (type == USERNAME) return MessageAttributeType.Username;
		if (type == PASSWORD) return MessageAttributeType.Password;
		if (type == MESSAGEINTEGRITY) return MessageAttributeType.MessageIntegrity;
		if (type == ERRORCODE) return MessageAttributeType.ErrorCode;
		if (type == UNKNOWNATTRIBUTE) return MessageAttributeType.UnknownAttribute;
		if (type == REFLECTEDFROM) return MessageAttributeType.ReflectedFrom;
		if (type == CHANNELNUMBER) return MessageAttributeType.ChannelNumber;
		if (type == LIFETIME) return MessageAttributeType.Lifetime;
		if (type == XORPEERADDRESS) return MessageAttributeType.XorPeerAddress;
		if (type == DATA) return MessageAttributeType.Data;
		if (type == REALM) return MessageAttributeType.Realm;
		if (type == NONCE) return MessageAttributeType.Nonce;
		if (type == XORRELAYEDADDRESS) return MessageAttributeType.XorRelayedAddress;
		if (type == EVENPORT) return MessageAttributeType.EvenPort;
		if (type == REQUESTEDTRANSPORT) return MessageAttributeType.RequestedTransport;
		if (type == DONTFRAGMENT) return MessageAttributeType.DontFragment;
		if (type == MESSAGEINTEGRITYSHA256) return MessageAttributeType.MessageIntegritySha256;
		if (type == XORMAPPEDADDRESS || type == XORMAPPEDADDRESS_OPTIONAL) return MessageAttributeType.XorMappedAddress;
		if (type == RESERVATIONTOKEN) return MessageAttributeType.ReservationToken;
		if (type == PRIORITY) return MessageAttributeType.Priority;
		if (type == PADDING) return MessageAttributeType.Padding;
		if (type == RESPONSEPORT) return MessageAttributeType.ResponsePort;
		if (type == SOFTWARE) return MessageAttributeType.Software;
		if (type == ALTERNATESERVER) return MessageAttributeType.AlternateServer;
		if (type == FINGERPRINT) return MessageAttributeType.Fingerprint;
		if (type == USERHASH) return MessageAttributeType.Userhash;
		if (type == RESPONSEORIGIN) return MessageAttributeType.ResponseOrigin;
		if (type == OTHERADDRESS) return MessageAttributeType.OtherAddress;
		if (type == DUMMY) return MessageAttributeType.Dummy;
		return null;
	}
	
	abstract public byte[] getBytes() throws UtilityException;
	//abstract public MessageAttribute parse(byte[] data) throws MessageAttributeParsingException;
	
	public int getLength() throws UtilityException {
		int length = getBytes().length;
		return length;
	}
	
	public static MessageAttribute parseCommonHeader(byte[] data) throws MessageAttributeParsingException {
		return parseCommonHeader(data, null);
	}

	public static MessageAttribute parseCommonHeader(byte[] data, byte[] transactionId) throws MessageAttributeParsingException {
		try {			
			byte[] typeArray = new byte[2];
			System.arraycopy(data, 0, typeArray, 0, 2);
			int type = Utility.twoBytesToInteger(typeArray);
			byte[] lengthArray = new byte[2];
			System.arraycopy(data, 2, lengthArray, 0, 2);
			int lengthValue = Utility.twoBytesToInteger(lengthArray);
			byte[] valueArray = new byte[lengthValue];
			System.arraycopy(data, 4, valueArray, 0, lengthValue);
			MessageAttribute ma;
			switch (type) {
			case MAPPEDADDRESS: ma = MappedAddress.parse(valueArray); break;
			case RESPONSEADDRESS: ma = ResponseAddress.parse(valueArray); break;
			case CHANGEREQUEST: ma = ChangeRequest.parse(valueArray); break;
			case SOURCEADDRESS: ma = SourceAddress.parse(valueArray); break;
			case CHANGEDADDRESS: ma = ChangedAddress.parse(valueArray); break;
			case USERNAME: ma = Username.parse(valueArray); break;
			case PASSWORD: ma = Password.parse(valueArray); break;
			case MESSAGEINTEGRITY: ma = MessageIntegrity.parse(valueArray); break;
			case ERRORCODE: ma = ErrorCode.parse(valueArray); break;
			case UNKNOWNATTRIBUTE: ma = UnknownAttribute.parse(valueArray); break;
			case REFLECTEDFROM: ma = ReflectedFrom.parse(valueArray); break;
			case CHANNELNUMBER: ma = ChannelNumber.parse(valueArray); break;
			case LIFETIME: ma = Lifetime.parse(valueArray); break;
			case XORPEERADDRESS: ma = XorPeerAddress.parse(valueArray, transactionId); break;
			case DATA: ma = Data.parse(valueArray); break;
			case REALM: ma = Realm.parse(valueArray); break;
			case NONCE: ma = Nonce.parse(valueArray); break;
			case XORRELAYEDADDRESS: ma = XorRelayedAddress.parse(valueArray, transactionId); break;
			case EVENPORT: ma = EvenPort.parse(valueArray); break;
			case REQUESTEDTRANSPORT: ma = RequestedTransport.parse(valueArray); break;
			case DONTFRAGMENT: ma = DontFragment.parse(valueArray); break;
			case MESSAGEINTEGRITYSHA256: ma = MessageIntegritySha256.parse(valueArray); break;
			case XORMAPPEDADDRESS:
			case XORMAPPEDADDRESS_OPTIONAL:
				ma = XorMappedAddress.parse(valueArray, transactionId);
				break;
			case RESERVATIONTOKEN: ma = ReservationToken.parse(valueArray); break;
			case PRIORITY: ma = Priority.parse(valueArray); break;
			case PADDING: ma = Padding.parse(valueArray); break;
			case RESPONSEPORT: ma = ResponsePort.parse(valueArray); break;
			case SOFTWARE: ma = Software.parse(valueArray); break;
			case ALTERNATESERVER: ma = AlternateServer.parse(valueArray); break;
			case FINGERPRINT: ma = Fingerprint.parse(valueArray); break;
			case USERHASH: ma = Userhash.parse(valueArray); break;
			case RESPONSEORIGIN: ma = ResponseOrigin.parse(valueArray); break;
			case OTHERADDRESS: ma = OtherAddress.parse(valueArray); break;
			default:
				if (type <= 0x7fff) {
					LOGGER.warn("Unknown comprehension-required MessageAttribute with type 0x{}.", Integer.toHexString(type));
					throw new UnknownMessageAttributeException("Unkown mandatory message attribute", intToType(type));
				} else {
					LOGGER.debug("Unknown comprehension-optional MessageAttribute with type 0x{} ignored.", Integer.toHexString(type));
					ma = Dummy.parse(valueArray);
					break;
				}
			}
			return ma;
		} catch (UtilityException ue) {
			throw new MessageAttributeParsingException("Parsing error");
		}
	}
}
