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

public interface MessageAttributeInterface {
	public enum MessageAttributeType { MappedAddress, ResponseAddress, ChangeRequest, SourceAddress, ChangedAddress, Username, Password, MessageIntegrity, ErrorCode, UnknownAttribute, ReflectedFrom, Realm, Nonce, XorMappedAddress, Padding, ResponsePort, Software, AlternateServer, Fingerprint, ResponseOrigin, OtherAddress, Dummy };
	final static int MAPPEDADDRESS = 0x0001;
	final static int RESPONSEADDRESS = 0x0002;
	final static int CHANGEREQUEST = 0x0003;
	final static int SOURCEADDRESS = 0x0004;
	final static int CHANGEDADDRESS = 0x0005;
	final static int USERNAME = 0x0006;
	final static int PASSWORD = 0x0007;
	final static int MESSAGEINTEGRITY = 0x0008;
	final static int ERRORCODE = 0x0009;
	final static int UNKNOWNATTRIBUTE = 0x000a;
	final static int REFLECTEDFROM = 0x000b;
	final static int REALM = 0x0014;
	final static int NONCE = 0x0015;
	final static int XORMAPPEDADDRESS = 0x0020;
	final static int PADDING = 0x0026;
	final static int RESPONSEPORT = 0x0027;
	final static int XORMAPPEDADDRESS_OPTIONAL = 0x8020;
	final static int SOFTWARE = 0x8022;
	final static int ALTERNATESERVER = 0x8023;
	final static int FINGERPRINT = 0x8028;
	final static int RESPONSEORIGIN = 0x802b;
	final static int OTHERADDRESS = 0x802c;
	final static int DUMMY = 0x0000;
}