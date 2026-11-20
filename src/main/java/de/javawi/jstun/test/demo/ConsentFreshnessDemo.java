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

package de.javawi.jstun.test.demo;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import de.javawi.jstun.consent.ConsentListener;
import de.javawi.jstun.consent.ConsentResponder;
import de.javawi.jstun.consent.ConsentSession;

/**
 * CLI demonstration of RFC 7675 STUN Usage for Consent Freshness.
 * <p>
 * With no arguments, runs a self-contained loopback demo showing initial consent,
 * authenticated application data sending, and immediate {@code 403 Forbidden} revocation.
 * With {@code <host> <port> <username> <password>}, runs a live consent check against
 * a remote ICE/RFC 7675 peer.
 */
public class ConsentFreshnessDemo {

	public static void main(String[] args) throws Exception {
		if (args.length >= 4) {
			String host = args[0];
			int port = Integer.parseInt(args[1]);
			String username = args[2];
			String password = args[3];
			InetSocketAddress peer = new InetSocketAddress(InetAddress.getByName(host), port);
			CountDownLatch obtained = new CountDownLatch(1);
			try (ConsentSession session = new ConsentSession(
					InetAddress.getByName("0.0.0.0"), peer, username, password)) {
				session.setListener(new ConsentListener() {
					@Override
					public void onConsentObtained(ConsentSession s) {
						System.out.println("Consent OBTAINED with " + s.getRemotePeer());
						obtained.countDown();
					}

					@Override
					public void onConsentRefreshed(ConsentSession s, long rttMs) {
						System.out.println("Consent refreshed (RTT=" + rttMs + " ms, remaining="
								+ s.getRemainingConsentMs() + " ms)");
					}

					@Override
					public void onConsentRevoked(ConsentSession s, String reason) {
						System.out.println("Consent REVOKED: " + reason);
					}

					@Override
					public void onConsentExpired(ConsentSession s) {
						System.out.println("Consent EXPIRED");
					}
				});
				session.start();
				if (!obtained.await(5, TimeUnit.SECONDS)) {
					System.out.println("No consent response received within 5 seconds (state="
							+ session.getState() + ").");
				}
			}
			return;
		}

		// Self-contained loopback demonstration
		InetAddress loopback = InetAddress.getByName("127.0.0.1");
		String ufragPair = "remoteUfrag:localUfrag";
		String icePassword = "VOkJxbRl1RmTxUk/WvJxBt";

		CountDownLatch obtained = new CountDownLatch(1);
		CountDownLatch revoked = new CountDownLatch(1);

		try (ConsentResponder responder = new ConsentResponder(loopback, 0, ufragPair, icePassword)) {
			responder.start();
			try (ConsentSession session = new ConsentSession(
					loopback, responder.getLocalAddress(), ufragPair, icePassword)) {
				session.setListener(new ConsentListener() {
					@Override
					public void onConsentObtained(ConsentSession s) {
						System.out.println("[RFC 7675] Consent OBTAINED for " + s.getRemotePeer());
						obtained.countDown();
					}

					@Override
					public void onConsentRefreshed(ConsentSession s, long rttMs) {
						System.out.println("[RFC 7675] Consent refreshed (RTT=" + rttMs + " ms, remaining="
								+ s.getRemainingConsentMs() + " ms)");
					}

					@Override
					public void onConsentRevoked(ConsentSession s, String reason) {
						System.out.println("[RFC 7675] Consent REVOKED: " + reason);
						revoked.countDown();
					}
				});

				session.start();
				if (obtained.await(3, TimeUnit.SECONDS)) {
					session.sendApplicationData("hello-consented-peer".getBytes(StandardCharsets.UTF_8));
					System.out.println("[RFC 7675] Application data permitted and sent (state="
							+ session.getState() + ").");
					responder.setConsentGranted(false);
					session.sendConsentCheck();
					revoked.await(3, TimeUnit.SECONDS);
					System.out.println("[RFC 7675] Final state: " + session.getState()
							+ ", canSendApplicationData=" + session.canSendApplicationData());
				}
			}
		}
	}
}
