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
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import de.javawi.jstun.consent.ConsentListener;
import de.javawi.jstun.consent.ConsentResponder;
import de.javawi.jstun.consent.ConsentSession;

/**
 * CLI demonstration of RFC 7675 STUN Usage for Consent Freshness.
 * <p>
 * With no positional arguments, runs a self-contained loopback demo showing initial consent,
 * authenticated application data sending, and immediate {@code 403 Forbidden} revocation
 * (use {@code -4}/{@code --ipv4} for {@code 127.0.0.1} or {@code -6}/{@code --ipv6} for {@code ::1}).
 * With {@code [-4|-6] <host> <port> <username> <password>}, runs a live consent check against
 * a remote ICE/RFC 7675 peer.
 */
public class ConsentFreshnessDemo {

	public static void main(String[] args) throws Exception {
		DemoIpVersion.ParsedArgs parsed;
		try {
			parsed = DemoIpVersion.parse(args);
		} catch (IllegalArgumentException iae) {
			System.err.println("Error: " + iae.getMessage());
			System.err.println("usage: java de.javawi.jstun.test.demo.ConsentFreshnessDemo [-4|--ipv4 | -6|--ipv6] [HOST PORT USERNAME PASSWORD]");
			return;
		}
		DemoIpVersion ipVersion = parsed.getIpVersion();
		List<String> pos = parsed.getPositionalArgs();
		if (pos.size() != 0 && pos.size() != 4) {
			System.err.println("usage: java de.javawi.jstun.test.demo.ConsentFreshnessDemo [-4|--ipv4 | -6|--ipv6] [HOST PORT USERNAME PASSWORD]");
			return;
		}

		if (pos.size() == 4) {
			String host = pos.get(0);
			int port = Integer.parseInt(pos.get(1));
			String username = pos.get(2);
			String password = pos.get(3);
			InetAddress peerAddr = ipVersion.resolveHost(host);
			InetAddress localBind = ipVersion.wildcardForTarget(peerAddr);
			InetSocketAddress peer = new InetSocketAddress(peerAddr, port);
			CountDownLatch obtained = new CountDownLatch(1);
			try (ConsentSession session = new ConsentSession(localBind, peer, username, password)) {
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
		InetAddress loopback = ipVersion.loopbackAddress();
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
