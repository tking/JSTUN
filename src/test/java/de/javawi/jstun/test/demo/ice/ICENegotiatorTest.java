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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

	@Test
	public void testAllCandidateTypesPriorityOrderingAndProperties() throws Exception {
		Candidate local = new Candidate(new Address("127.0.0.1"), (short) 1);
		try {
			Candidate srflx = new Candidate(new Address("203.0.113.10"), 50001, CandidateType.ServerReflexive, (short) 1, local);
			Candidate prflx = new Candidate(new Address("203.0.113.11"), 50002, CandidateType.PeerReflexive, (short) 1, local);
			Candidate relay = new Candidate(new Address("198.51.100.5"), 60000, CandidateType.Relayed, (short) 1, local);

			ICENegotiator negotiator = new ICENegotiator("127.0.0.1", 3478, (short) 1);
			negotiator.candidates.add(local);
			negotiator.candidates.add(srflx);
			negotiator.candidates.add(prflx);
			negotiator.candidates.add(relay);

			negotiator.prioritizeCandidates();
			List<Candidate> sorted = negotiator.getSortedCandidates();
			assertEquals(4, sorted.size());
			assertEquals(CandidateType.Relayed, sorted.get(0).getCandidateType());
			assertEquals(CandidateType.PeerReflexive, sorted.get(1).getCandidateType());
			assertEquals(CandidateType.ServerReflexive, sorted.get(2).getCandidateType());
			assertEquals(CandidateType.Local, sorted.get(3).getCandidateType());

			// Verify exact ICE priority formula: ((1 << 24) * typeValue) + ((1 << 8) * localValue) + componentId
			assertEquals(((1 << 24) * 126) + ((1 << 8) * 1) + 1, relay.getPriority());
			assertEquals(((1 << 24) * 84) + ((1 << 8) * 1) + 1, prflx.getPriority());
			assertEquals(((1 << 24) * 42) + ((1 << 8) * 1) + 1, srflx.getPriority());
			assertEquals(((1 << 24) * 0) + ((1 << 8) * 1) + 1, local.getPriority());

			// Foundation, inUse, base, equals/hashCode, and componentId validation
			srflx.setFoundationId(7);
			assertEquals(7, srflx.getFoundationId());
			srflx.setInUse(true);
			assertTrue(srflx.getInUse());
			srflx.setBase(local);
			assertEquals(local, srflx.getBase());

			Candidate duplicateSrflx = new Candidate(new Address("203.0.113.10"), 50001, CandidateType.ServerReflexive, (short) 1, local);
			assertEquals(srflx, duplicateSrflx);
			assertEquals(srflx.hashCode(), duplicateSrflx.hashCode());
			assertFalse(srflx.equals("notACandidate"));

			assertThrows(IllegalArgumentException.class, () -> srflx.setComponentId((short) 0));
			assertThrows(IllegalArgumentException.class, () -> srflx.setComponentId((short) 257));
		} finally {
			local.closeSocket();
		}
	}
}
