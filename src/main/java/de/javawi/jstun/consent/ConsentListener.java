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
 * Callback interface for observing RFC 7675 consent freshness state changes.
 */
public interface ConsentListener {

	/**
	 * Invoked when consent first transitions from {@link ConsentState#INITIAL}
	 * to {@link ConsentState#ACTIVE}.
	 */
	default void onConsentObtained(ConsentSession session) {
	}

	/**
	 * Invoked whenever a valid, authenticated, non-error STUN Binding Response
	 * refreshes consent, with the measured transaction round-trip time in milliseconds.
	 */
	default void onConsentRefreshed(ConsentSession session, long rttMs) {
	}

	/**
	 * Invoked when consent expires after the 30-second expiry window elapses
	 * without a valid authenticated response (RFC 7675 §5.1).
	 */
	default void onConsentExpired(ConsentSession session) {
	}

	/**
	 * Invoked when consent is immediately revoked by an authenticated STUN
	 * {@code 403 Forbidden} error response or an authenticated close event
	 * (RFC 7675 §5.2).
	 */
	default void onConsentRevoked(ConsentSession session, String reason) {
	}
}
