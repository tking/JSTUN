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

/**
 * Exception thrown when a TURN (RFC 5766) operation fails due to a protocol
 * error response or transport failure.
 */
public class TurnException extends Exception {
	private static final long serialVersionUID = 1L;
	private final int errorCode;

	public TurnException(String message) {
		super(message);
		this.errorCode = -1;
	}

	public TurnException(String message, Throwable cause) {
		super(message, cause);
		this.errorCode = -1;
	}

	public TurnException(int errorCode, String reason) {
		super("TURN error " + errorCode + (reason != null && !reason.isEmpty() ? ": " + reason : ""));
		this.errorCode = errorCode;
	}

	public int getErrorCode() {
		return errorCode;
	}
}
