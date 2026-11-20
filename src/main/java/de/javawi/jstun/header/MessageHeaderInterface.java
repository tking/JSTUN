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

public interface MessageHeaderInterface {
	public enum MessageHeaderType {
		BindingRequest, BindingResponse, BindingErrorResponse, BindingIndication,
		SharedSecretRequest, SharedSecretResponse, SharedSecretErrorResponse,
		AllocateRequest, AllocateResponse, AllocateErrorResponse,
		RefreshRequest, RefreshResponse, RefreshErrorResponse,
		SendIndication, DataIndication,
		CreatePermissionRequest, CreatePermissionResponse, CreatePermissionErrorResponse,
		ChannelBindRequest, ChannelBindResponse, ChannelBindErrorResponse
	};
	final static int MAGIC_COOKIE = 0x2112A442;
	final static int BINDINGREQUEST = 0x0001;
	final static int BINDINGINDICATION = 0x0011;
	final static int BINDINGRESPONSE = 0x0101;
	final static int BINDINGERRORRESPONSE = 0x0111;
	final static int SHAREDSECRETREQUEST = 0x0002;
	final static int SHAREDSECRETRESPONSE = 0x0102;
	final static int SHAREDSECRETERRORRESPONSE = 0x0112;
	// RFC 5766 (TURN) message types
	final static int ALLOCATEREQUEST = 0x0003;
	final static int ALLOCATERESPONSE = 0x0103;
	final static int ALLOCATEERRORRESPONSE = 0x0113;
	final static int REFRESHREQUEST = 0x0004;
	final static int REFRESHRESPONSE = 0x0104;
	final static int REFRESHERRORRESPONSE = 0x0114;
	final static int SENDINDICATION = 0x0016;
	final static int DATAINDICATION = 0x0017;
	final static int CREATEPERMISSIONREQUEST = 0x0008;
	final static int CREATEPERMISSIONRESPONSE = 0x0108;
	final static int CREATEPERMISSIONERRORRESPONSE = 0x0118;
	final static int CHANNELBINDREQUEST = 0x0009;
	final static int CHANNELBINDRESPONSE = 0x0109;
	final static int CHANNELBINDERRORRESPONSE = 0x0119;
}