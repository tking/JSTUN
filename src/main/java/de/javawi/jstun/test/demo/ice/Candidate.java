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

import java.net.DatagramSocket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Objects;

import de.javawi.jstun.util.Address;
import de.javawi.jstun.util.UtilityException;

public class Candidate implements Comparable<Candidate> {
	// The ieft-mmusic-ice-12 draft is not non-ambigious about the number of types.
	// Chapter 5.1 defines 3 and 4 types on page 16 and page 17, respectively.
	public enum CandidateType {
		Local, ServerReflexive, PeerReflexive, Relayed
	};

	private DatagramSocket socket;
	private Address address;
	private int port;
	private CandidateType type;
	private short componentId;
	private int priority;
	private int foundationId;
	private Candidate base;
	private boolean isInUse;

	public Candidate(Address address, short componentId)
			throws SocketException, UnknownHostException, UtilityException {
		this.socket = new DatagramSocket(0, address.getInetAddress());
		this.address = address;
		this.port = this.socket.getLocalPort();
		this.type = CandidateType.Local;
		setComponentId(componentId);
		this.priority = 0;
		this.base = this;
		this.isInUse = false;
	}

	public Candidate(Address address, CandidateType type, short componentId, Candidate base)
			throws SocketException, UnknownHostException, UtilityException {
		this(address, (base != null) ? base.getPort() : 0, type, componentId, base);
	}

	public Candidate(Address address, int port, CandidateType type, short componentId, Candidate base)
			throws SocketException, UnknownHostException, UtilityException {
		if (type == CandidateType.Local) {
			this.socket = new DatagramSocket(port, address.getInetAddress());
			this.address = address;
			this.port = this.socket.getLocalPort();
			this.base = (base != null) ? base : this;
		} else {
			// Non-local candidates (e.g. ServerReflexive with a NAT's public IP) cannot bind
			// a local socket to the remote/public address; they share their base candidate's socket.
			this.socket = (base != null) ? base.socket : null;
			this.address = address;
			this.port = (port > 0) ? port : ((base != null) ? base.getPort() : 0);
			this.base = (base != null) ? base : this;
		}
		this.type = type;
		setComponentId(componentId);
		this.priority = 0;
		this.isInUse = false;
	}

	public void setBase(Candidate base) {
		this.base = base;
	}

	public Candidate getBase() {
		return base;
	}

	public CandidateType getCandidateType() {
		return type;
	}

	public void setComponentId(short componentId) {
		if ((componentId < 1) || (componentId > 256))
			throw new IllegalArgumentException(componentId + " is not between 1 and 256 inclusive.");
		this.componentId = componentId;
	}

	public short getComponentId() {
		return componentId;
	}

	public void setFoundationId(int foundationId) {
		this.foundationId = foundationId;
	}

	public int getFoundationId() {
		return foundationId;
	}

	public void setPriority(int priority) {
		this.priority = priority;
	}

	public int getPriority() {
		return priority;
	}

	public Address getAddress() throws UtilityException {
		if (address != null) {
			return address;
		}
		return new Address(socket.getLocalAddress().getAddress());
	}

	public int getPort() {
		if (port > 0) {
			return port;
		}
		return (socket != null) ? socket.getLocalPort() : 0;
	}

	public void setInUse(boolean isInUse) {
		this.isInUse = isInUse;
	}

	public boolean getInUse() {
		return isInUse;
	}

	public void closeSocket() {
		if (socket != null && !socket.isClosed()) {
			socket.close();
		}
	}

	@Override
	public int compareTo(Candidate cand) {
		return Integer.compare(cand.getPriority(), getPriority());
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (!(o instanceof Candidate))
			return false;
		Candidate other = (Candidate) o;
		return port == other.port
				&& componentId == other.componentId
				&& type == other.type
				&& Objects.equals(address, other.address);
	}

	@Override
	public int hashCode() {
		return Objects.hash(address, port, type, componentId);
	}
}
