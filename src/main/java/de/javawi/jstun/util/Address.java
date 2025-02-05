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

package de.javawi.jstun.util;

import java.util.*;
import java.net.*;

public class Address {
	int[] octets;
	
	public Address(int firstOctet, int secondOctet, int thirdOctet, int fourthOctet) throws UtilityException {
		// Deprecated: IPv4 Parsing, use Address(int[] octets) instead
		if ((firstOctet < 0) || (firstOctet > 255) || (secondOctet < 0) || (secondOctet > 255) || (thirdOctet < 0) || (thirdOctet > 255) || (fourthOctet < 0) || (fourthOctet > 255)) {
			throw new UtilityException("Address is malformed.");
		}
		this.octets = new int[4];
		this.octets[0] = firstOctet;
		this.octets[1] = secondOctet;
		this.octets[2] = thirdOctet;
		this.octets[3] = fourthOctet;
	}

	public Address(int[] octets) throws UtilityException {
		if (octets.length != 4 && octets.length != 16) {
			throw new UtilityException("4 or 16 octets are required.");
		}
        for (int octet : octets) {
            if ((octet < 0) || (octet > 255)) {
                throw new UtilityException("Address is malformed.");
            }
        }
		this.octets = octets;
	}
	
	public Address(String address) throws UtilityException {
		// ipv4
		if (address.contains(".")) {
			StringTokenizer st = new StringTokenizer(address, ".");
			if (st.countTokens() != 4) {
				throw new UtilityException("4 octets in address string are required.");
			}
			int i = 0;
			this.octets = new int[4];
			while (st.hasMoreTokens()) {
				int temp = Integer.parseInt(st.nextToken());
				if ((temp < 0) || (temp > 255)) {
					throw new UtilityException("Address is in incorrect format.");
				}
				this.octets[i] = temp;
				i++;
			}
		} else {
			// ipv6
			StringTokenizer st = new StringTokenizer(address, ":");
			if (st.countTokens() != 8) {
				throw new UtilityException("8 hex values in address string are required.");
			}
			int i = 0;
			this.octets = new int[16];
			while (st.hasMoreTokens()) {
				int temp = Integer.parseInt(st.nextToken(), 16);
				if ((temp < 0) || (temp > 65535)) {
					throw new UtilityException("Address is in incorrect format.");
				}
				this.octets[i] = temp / 256;
				this.octets[i + 1] = temp % 256;
				i += 2;
			}
		}
	}
	
	public Address(byte[] address) throws UtilityException {
		if (address.length != 4 && address.length != 16) {
			throw new UtilityException("4 or 16 bytes are required.");
		}
		this.octets = new int[address.length];
		for (int i = 0; i < address.length; i++) {
			this.octets[i] = Utility.oneByteToInteger(address[i]);
		}
	}
	
	public String toString() {
		if (this.octets.length == 4) {
			return octets[0] + "." + octets[1] + "." + octets[2] + "." + octets[3];
		} else {
			StringBuilder result = new StringBuilder();
			for (int i = 0; i < 16; i+=2) {
				int currentVal = octets[i] * 256 + octets[i + 1];
				result.append(Integer.toHexString(currentVal));
				if (i < 14) {
					result.append(":");
				}
			}
			return result.toString();
		}
	}
	
	public byte[] getBytes() throws UtilityException {
		byte[] result = new byte[octets.length];
		for (int i = 0; i < octets.length; i++) {
			result[i] = Utility.integerToOneByte(octets[i]);
		}
		return result;
	}
	
	public InetAddress getInetAddress() throws UtilityException, UnknownHostException {
		return InetAddress.getByAddress(this.getBytes());
	}
	
	public boolean equals(Object obj) {
		if (obj == null) return false;
		try {
			byte[] data1 = this.getBytes();
			byte[] data2 = ((Address) obj).getBytes();
            return Arrays.equals(data1, data2);
        } catch (UtilityException ue) {
			return false;
		}
	}
	
	public int hashCode() {
		int result = 0;
		for (int i = 0; i < octets.length; i++) {
			result += octets[i] << (i * 8);
		}
		return result;
	}

}
