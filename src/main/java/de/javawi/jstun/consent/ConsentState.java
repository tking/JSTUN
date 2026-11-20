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

package de.javawi.jstun.consent;

/**
 * Lifecycle state of an RFC 7675 STUN Consent Freshness session on a single 5-tuple.
 */
public enum ConsentState {
	/**
	 * Initial state before consent has been obtained. Application data MUST NOT
	 * be transmitted until consent transitions to {@link #ACTIVE} (RFC 7675 §5.1).
	 */
	INITIAL,

	/**
	 * Peer consent is currently fresh and application data may be transmitted on
	 * the 5-tuple while periodic STUN consent checks maintain freshness.
	 */
	ACTIVE,

	/**
	 * Consent expired because no valid, authenticated, non-error STUN Binding
	 * Response was received within the 30-second expiry window (RFC 7675 §5.1).
	 * Transmission MUST cease and the same ICE credentials MUST NOT be reused.
	 */
	EXPIRED,

	/**
	 * Consent was immediately revoked by an authenticated STUN {@code 403 Forbidden}
	 * response or an authenticated transport closure such as a TLS fatal alert
	 * (RFC 7675 §5.2). Transmission MUST cease and the same ICE credentials MUST NOT
	 * be reused.
	 */
	REVOKED
}
