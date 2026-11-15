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

package de.javawi.jstun.test.demo.ice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.test.demo.ice.Candidate.CandidateType;
import de.javawi.jstun.util.Address;

public class ICENegotiatorTest {

	@Test
	public void testServerReflexiveCandidateDoesNotBindRemotePublicIP() throws Exception {
		Candidate local = new Candidate(new Address("127.0.0.1"), (short) 1);
		try {
			// 203.0.113.42 is a TEST-NET-3 public IP not assigned to any local interface;
			// previously this threw BindException: Can't assign requested address (Issue #2)
			Candidate srflx = new Candidate(
					new Address("203.0.113.42"),
					54321,
					CandidateType.ServerReflexive,
					(short) 1,
					local);

			assertEquals(new Address("203.0.113.42"), srflx.getAddress());
			assertEquals(54321, srflx.getPort());
			assertEquals(local, srflx.getBase());

			ICENegotiator negotiator = new ICENegotiator((short) 1);
			negotiator.candidates.add(local);
			negotiator.candidates.add(srflx);
			assertEquals(2, negotiator.candidates.size());

			negotiator.prioritizeCandidates();
			List<Candidate> sorted = negotiator.getSortedCandidates();
			assertEquals(2, sorted.size());
			assertEquals(CandidateType.ServerReflexive, sorted.get(0).getCandidateType());
			assertEquals(CandidateType.Local, sorted.get(1).getCandidateType());
			assertTrue(sorted.get(0).getPriority() > sorted.get(1).getPriority());
		} finally {
			local.closeSocket();
		}
	}
}
