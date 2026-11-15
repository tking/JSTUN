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

package de.javawi.jstun.test;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;

public class DiscoveryInfo {
	public enum MappingBehavior {
		UNKNOWN,
		DIRECT,
		ENDPOINT_INDEPENDENT,
		ADDRESS_DEPENDENT,
		ADDRESS_AND_PORT_DEPENDENT
	}

	public enum FilteringBehavior {
		UNKNOWN,
		ENDPOINT_INDEPENDENT,
		ADDRESS_DEPENDENT,
		ADDRESS_AND_PORT_DEPENDENT
	}

	private InetAddress testIP;
	private boolean error = false;
	private int errorResponseCode = 0;
	private String errorReason;
	private boolean openAccess = false;
	private boolean blockedUDP = false;
	private boolean fullCone = false;
	private boolean restrictedCone = false;
	private boolean portRestrictedCone = false;
	private boolean symmetric = false;
	private boolean symmetricUDPFirewall = false;
	private InetAddress publicIP;
	private int publicPort = -1;
	private MappingBehavior mappingBehavior = MappingBehavior.UNKNOWN;
	private FilteringBehavior filteringBehavior = FilteringBehavior.UNKNOWN;
	
	public DiscoveryInfo(InetAddress testIP) {
		this.testIP = testIP;
	}
	
	public boolean isError() {
		return error;
	}
	
	public void setError(int responseCode, String reason) {
		this.error = true;
		this.errorResponseCode = responseCode;
		this.errorReason = reason;
	}
	
	public boolean isOpenAccess() {
		if (error) return false;
		return openAccess;
	}

	public void setOpenAccess() {
		this.openAccess = true;
	}

	public boolean isBlockedUDP() {
		if (error) return false;
		return blockedUDP;
	}

	public void setBlockedUDP() {
		this.blockedUDP = true;
	}
	
	public boolean isFullCone() {
		if (error) return false;
		return fullCone;
	}

	public void setFullCone() {
		this.fullCone = true;
	}

	public boolean isPortRestrictedCone() {
		if (error) return false;
		return portRestrictedCone;
	}

	public void setPortRestrictedCone() {
		this.portRestrictedCone = true;
	}

	public boolean isRestrictedCone() {
		if (error) return false;
		return restrictedCone;
	}

	public void setRestrictedCone() {
		this.restrictedCone = true;
	}

	public boolean isSymmetric() {
		if (error) return false;
		return symmetric;
	}

	public void setSymmetric() {
		this.symmetric = true;
	}

	public boolean isSymmetricUDPFirewall() {
		if (error) return false;
		return symmetricUDPFirewall;
	}

	public void setSymmetricUDPFirewall() {
		this.symmetricUDPFirewall = true;
	}
	
	public InetAddress getPublicIP() {
		return publicIP;
	}
	
	public InetAddress getLocalIP() {
		return testIP;
	}
	
	public void setPublicIP(InetAddress publicIP) {
		this.publicIP = publicIP;
	}
	
	public int getPublicPort() {
		return publicPort;
	}
	
	public void setPublicPort(int publicPort) {
		this.publicPort = publicPort;
	}

	public MappingBehavior getMappingBehavior() {
		if (error) return MappingBehavior.UNKNOWN;
		return mappingBehavior;
	}

	public void setMappingBehavior(MappingBehavior mappingBehavior) {
		this.mappingBehavior = (mappingBehavior != null) ? mappingBehavior : MappingBehavior.UNKNOWN;
	}

	public FilteringBehavior getFilteringBehavior() {
		if (error) return FilteringBehavior.UNKNOWN;
		return filteringBehavior;
	}

	public void setFilteringBehavior(FilteringBehavior filteringBehavior) {
		this.filteringBehavior = (filteringBehavior != null) ? filteringBehavior : FilteringBehavior.UNKNOWN;
	}
	
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("Network interface: ");
		try {
			NetworkInterface ni = NetworkInterface.getByInetAddress(testIP);
			sb.append(ni != null ? ni.getName() : "unknown");
		} catch (SocketException se) {
			sb.append("unknown");
		}
		sb.append("\n");
		sb.append("Local IP address: ");
		sb.append(testIP.getHostAddress());
		sb.append("\n");
		if (error) {
			sb.append(errorReason + " - Responsecode: " + errorResponseCode);
			return sb.toString();
		}
		sb.append("Result: ");
		if (openAccess) sb.append("Open access to the Internet.\n");
		if (blockedUDP) sb.append("Firewall blocks UDP.\n");
		if (fullCone) sb.append("Full Cone NAT handles connections.\n");
		if (restrictedCone) sb.append("Restricted Cone NAT handles connections.\n");
		if (portRestrictedCone) sb.append("Port restricted Cone NAT handles connections.\n");
		if (symmetric) sb.append("Symmetric Cone NAT handles connections.\n");
		if (symmetricUDPFirewall) sb.append ("Symmetric UDP Firewall handles connections.\n");
		if (!openAccess && !blockedUDP && !fullCone && !restrictedCone && !portRestrictedCone && !symmetric && !symmetricUDPFirewall) sb.append("unkown\n");
		if (mappingBehavior != MappingBehavior.UNKNOWN) {
			sb.append("RFC 5780 Mapping Behavior: ").append(mappingBehavior.name()).append("\n");
		}
		if (filteringBehavior != FilteringBehavior.UNKNOWN) {
			sb.append("RFC 5780 Filtering Behavior: ").append(filteringBehavior.name()).append("\n");
		}
		sb.append("Public IP address: ");
		if (publicIP != null) {
			sb.append(publicIP.getHostAddress());
		} else {
			sb.append("unknown");
		}
		sb.append("\n");
		return sb.toString();
	}	
}
