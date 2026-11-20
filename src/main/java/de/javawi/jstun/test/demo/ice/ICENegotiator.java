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

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.test.DiscoveryInfo;
import de.javawi.jstun.test.DiscoveryTest;
import de.javawi.jstun.test.demo.ice.Candidate.CandidateType;
import de.javawi.jstun.turn.TurnClient;
import de.javawi.jstun.turn.TurnException;
import de.javawi.jstun.util.Address;
import de.javawi.jstun.util.UtilityException;

public class ICENegotiator {
	private static final Logger LOGGER = LoggerFactory.getLogger(ICENegotiator.class);
	// type preference must be an integer from 0 (=lowest) to 126 (=highest) (inclusive)
	private final static int LOCAL_PREFERENCE = 0;
	private final static int SERVER_REFLEXIVE_PREFERENCE = 42;
	private final static int PEER_REFLEXIVE_PREFERENCE = 84;
	private final static int RELAYED_PREFERENCE = 126;
	
	// component id
	private short componentId;
	private String stunServer = "jstun.t-king.de";
	private int stunPort = 3478;
	private String turnServer;
	private int turnPort = 3478;
	private String turnUsername;
	private String turnPassword;
	
	// candidates
	HashSet<Candidate> candidates;
	
	public ICENegotiator(short componentId) {
		this.componentId = componentId;
		candidates = new HashSet<Candidate>();
	}
	
	public ICENegotiator(String stunServer, int stunPort, short componentId) {
		this.stunServer = stunServer;
		this.stunPort = stunPort;
		this.componentId = componentId;
		candidates = new HashSet<Candidate>();
	}

	/**
	 * Configures an optional RFC 5766 TURN server so {@link #gatherCandidateAddresses()}
	 * also gathers {@link CandidateType#Relayed} candidates.
	 */
	public void setTurnServer(String turnServer, int turnPort, String turnUsername, String turnPassword) {
		this.turnServer = turnServer;
		this.turnPort = turnPort;
		this.turnUsername = turnUsername;
		this.turnPassword = turnPassword;
	}

	/**
	 * Allocates a single RFC 5766 relayed ICE candidate from the configured TURN server
	 * using {@code base} as the local base candidate.
	 */
	public Candidate gatherRelayedCandidate(InetAddress localAddress, Candidate base)
			throws TurnException, IOException, UtilityException, UnknownHostException {
		if (turnServer == null || turnUsername == null || turnPassword == null) {
			throw new IllegalStateException("TURN server credentials are not configured");
		}
		try (TurnClient turnClient = new TurnClient(localAddress, turnServer, turnPort, turnUsername, turnPassword)) {
			InetSocketAddress relayed = turnClient.allocate();
			Candidate relayedCand = new Candidate(
					new Address(relayed.getAddress().getAddress()),
					relayed.getPort(),
					CandidateType.Relayed,
					componentId,
					base);
			relayedCand.setComponentId(componentId);
			candidates.add(relayedCand);
			LOGGER.debug("Added relayed ICE candidate: {}:{}.", relayedCand.getAddress(), relayedCand.getPort());
			return relayedCand;
		}
	}

	/*
	 * This method gathers candidate addresses as described in draft-ietf-mmusic-ice-12.txt Chapter 2.1
	 * Unfortunately, only the candidates of the direct attached network interfaces and server reflexive
	 * addreses are gathered. So far, no support for relayed candidates is available (because I am not
	 * aware of any STUN relay server).
	 */
	public void gatherCandidateAddresses() {
		try {
			candidates = new HashSet<Candidate>();
			Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
			while (ifaces.hasMoreElements()) {
				NetworkInterface iface = ifaces.nextElement();
				Enumeration<InetAddress> iaddresses = iface.getInetAddresses();
				while (iaddresses.hasMoreElements()) {
					InetAddress iaddress = iaddresses.nextElement();
					if (!iaddress.isLoopbackAddress() && !iaddress.isLinkLocalAddress()) {
						try {
							// add host candidate
							Candidate local = new Candidate(new Address(iaddress.getAddress()), componentId);
							candidates.add(local);
							LOGGER.debug("Added local ICE host candidate: {}.", local.getAddress());
							// add server reflexive address
							DiscoveryTest test = new DiscoveryTest(iaddress, 0, stunServer, stunPort);
							DiscoveryInfo di = test.test();
							if (di.getPublicIP() != null && !di.isOpenAccess()) {
								Candidate cand = new Candidate(
										new Address(di.getPublicIP().getAddress()),
										di.getPublicPort(),
										CandidateType.ServerReflexive,
										componentId,
										local);
								cand.setComponentId(componentId);
								candidates.add(cand);
								LOGGER.debug("Added server-reflexive ICE candidate: {}:{}.", cand.getAddress(), cand.getPort());
							}
							if (turnServer != null && turnUsername != null && turnPassword != null) {
								try {
									gatherRelayedCandidate(iaddress, local);
								} catch (TurnException te) {
									LOGGER.debug("TurnException while gathering relayed ICE candidate: {}", te.getMessage());
								}
							}
						} catch (MessageHeaderParsingException mhpe) {
							LOGGER.debug("MessageHeaderParsingException while gathering candidate addresses: {}", mhpe.getMessage());
						} catch (MessageAttributeException mae) {
							LOGGER.debug("MessageAttributeException while gathering candidate addresses: {}", mae.getMessage());
						} catch (UtilityException ue) {
							LOGGER.debug("UtilityException while gathering candidate addresses: {}", ue.getMessage());
						} catch (UnknownHostException uhe) {
							LOGGER.debug("UnknownHostException while gathering candidate addresses: {}", uhe.getMessage());
						} catch (SocketException se) {
							LOGGER.debug("SocketException while gathering candidate addresses: {}", se.getMessage());
						} catch (IOException ioe) {
							LOGGER.debug("IOException while gathering candidate addresses: {}", ioe.getMessage());
						}
					}
				}
			}
			LOGGER.info("Gathered {} ICE candidate(s) for component {}.", candidates.size(), componentId);
		} catch (SocketException se) {
			LOGGER.warn("SocketException while enumerating network interfaces: {}", se.getMessage(), se);
		}
	}
	
	public void prioritizeCandidates() {
		// count number of candidate types
		int numberLocal = 0;
		int numberServerReflexive = 0;
		int numberPeerReflexive = 0;
		int numberRelayed = 0;
		// count number of candidates of a particular type
		Iterator<Candidate> iterCandidates = candidates.iterator();
		while (iterCandidates.hasNext()) {
			Candidate cand = iterCandidates.next();
			CandidateType type = cand.getCandidateType();
			if (type == CandidateType.Local) numberLocal++;
			else if (type == CandidateType.ServerReflexive) numberServerReflexive++;
			else if (type == CandidateType.PeerReflexive) numberPeerReflexive++;
			else if (type == CandidateType.Relayed) numberRelayed++;
		}
		// assign priorities
		iterCandidates = candidates.iterator();
		while (iterCandidates.hasNext()) {
			int typeValue = 0;
			int localValue = 0;
			int componentValue = 0;
			Candidate cand = iterCandidates.next();
			CandidateType type = cand.getCandidateType();
			if (type == CandidateType.Local) {
				typeValue = LOCAL_PREFERENCE;
				localValue = numberLocal--;
			}
			else if (type == CandidateType.ServerReflexive) {
				typeValue = SERVER_REFLEXIVE_PREFERENCE;
				localValue = numberServerReflexive--;
			}
			else if (type == CandidateType.PeerReflexive) {
				typeValue = PEER_REFLEXIVE_PREFERENCE;
				localValue = numberPeerReflexive--;
			}
			else if (type == CandidateType.Relayed) {
				typeValue = RELAYED_PREFERENCE;
				localValue = numberRelayed--;
			}
			componentValue = cand.getComponentId();
			int priority = ((1 << 24) * typeValue) + ((1 << 8) * localValue) + componentValue;
			cand.setPriority(priority);
			LOGGER.debug("Assigned priority {} to candidate (port={}, type={}).", priority, cand.getPort(), type);
		}
		LOGGER.info("Prioritized {} ICE candidate(s) for component {}.", candidates.size(), componentId);
	}
	
	public List<Candidate> getSortedCandidates() {
		Vector<Candidate> sortedCandidates = new Vector<Candidate>(candidates);
		Collections.sort(sortedCandidates);
		return sortedCandidates;
	}

	public static void main(String args[]) {
		ICENegotiator cc = new ICENegotiator((short) 1);
		// gather candidates
		cc.gatherCandidateAddresses();
		// priorize candidates
		cc.prioritizeCandidates();
		// get SortedCandidates
		List<Candidate> sortedCandidates = cc.getSortedCandidates();
		
		// sent sorted candidate addresses to peer over SDP
		// received sorted candidate addresses of peer over SDP
	}
}
