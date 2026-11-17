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

import java.io.IOException;
import java.net.*;
import java.util.Vector;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.SimpleFormatter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.attribute.ChangeRequest;
import de.javawi.jstun.attribute.ChangedAddress;
import de.javawi.jstun.attribute.MappedAddress;
import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.attribute.OtherAddress;
import de.javawi.jstun.attribute.ResponseAddress;
import de.javawi.jstun.attribute.ResponseOrigin;
import de.javawi.jstun.attribute.ResponsePort;
import de.javawi.jstun.attribute.SourceAddress;
import de.javawi.jstun.attribute.UnknownAttribute;
import de.javawi.jstun.attribute.UnknownMessageAttributeException;
import de.javawi.jstun.attribute.XorMappedAddress;
import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.util.Address;
import de.javawi.jstun.util.UtilityException;

/*
 * This class implements a STUN server as described in RFC 3489.
 * The server requires a machine that is dual-homed to be functional. 
 */
public class StunServer {
	private static final Logger LOGGER = LoggerFactory.getLogger(StunServer.class);
	Vector<DatagramSocket> sockets;
	private final Vector<StunServerReceiverThread> receiverThreads = new Vector<StunServerReceiverThread>();
	private volatile boolean doRun;
	
	public StunServer(int primaryPort, InetAddress primary, int secondaryPort, InetAddress secondary) throws SocketException {
		this(primaryPort, primary, secondaryPort, secondary, primaryPort, secondaryPort);
	}

	public StunServer(int primaryPort, InetAddress primary, int secondaryPort, InetAddress secondary,
			int secondaryIpPrimaryPort, int secondaryIpSecondaryPort) throws SocketException {
		sockets = new Vector<DatagramSocket>();
		sockets.add(new DatagramSocket(primaryPort, primary));
		sockets.add(new DatagramSocket(secondaryPort, primary));
		sockets.add(new DatagramSocket(secondaryIpPrimaryPort, secondary));
		sockets.add(new DatagramSocket(secondaryIpSecondaryPort, secondary));
	}
	
	public void start() throws SocketException {
		doRun = true;
		receiverThreads.clear();
		for (DatagramSocket socket : sockets) {
			socket.setReceiveBufferSize(2000);
			socket.setSoTimeout(500);
			StunServerReceiverThread ssrt = new StunServerReceiverThread(socket);
			receiverThreads.add(ssrt);
			ssrt.start();
		}
	}

	public void stop() {
		doRun = false;
		final long start = System.currentTimeMillis();
		for ( DatagramSocket socket : sockets ) {
			socket.close();
			// Wait for a wile to allow sockets to disconnect gracefully.
			while ( !socket.isClosed() && System.currentTimeMillis() - start < 7000 ) {
				try {
					Thread.sleep( 50 );
				} catch ( InterruptedException e ) {
					e.printStackTrace();
				}
			}
		}
		for (StunServerReceiverThread thread : receiverThreads) {
			long remaining = 7000 - (System.currentTimeMillis() - start);
			if (remaining > 0) {
				try {
					thread.join(remaining);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			}
		}
	}

	/*
	 * Inner class to handle incoming packets and react accordingly.
	 * I decided not to start a thread for every received Binding Request, because the time
	 * required to receive a Binding Request, parse it, generate a Binding Response and send
	 * it varies only between 2 and 4 milliseconds. This amount of time is small enough so
	 * that no extra thread is needed for incoming Binding Request. 
	 */
	class StunServerReceiverThread extends Thread {
		private DatagramSocket receiverSocket;
		private DatagramSocket changedPort;
		private DatagramSocket changedIP;
		private DatagramSocket changedPortIP;
		private final InetAddress receiverAddress;
		private final int receiverPort;
		private final InetAddress changedPortAddress;
		private final int changedPortPort;
		private final InetAddress changedIPAddress;
		private final int changedIPPort;
		private final InetAddress changedPortIPAddress;
		private final int changedPortIPPort;
		
		StunServerReceiverThread(DatagramSocket datagramSocket) {
			this.receiverSocket = datagramSocket;
			int idx = sockets.indexOf(receiverSocket);
			if (idx >= 0 && sockets.size() == 4) {
				changedPort = sockets.get(idx ^ 1);
				changedIP = sockets.get(idx ^ 2);
				changedPortIP = sockets.get(idx ^ 3);
			}
			this.receiverAddress = receiverSocket.getLocalAddress();
			this.receiverPort = receiverSocket.getLocalPort();
			this.changedPortAddress = changedPort.getLocalAddress();
			this.changedPortPort = changedPort.getLocalPort();
			this.changedIPAddress = changedIP.getLocalAddress();
			this.changedIPPort = changedIP.getLocalPort();
			this.changedPortIPAddress = changedPortIP.getLocalAddress();
			this.changedPortIPPort = changedPortIP.getLocalPort();
		}
		
		public void run() {
			while (doRun) {
				try {
					DatagramPacket receive = new DatagramPacket(new byte[200], 200);
					receiverSocket.receive(receive);
					LOGGER.debug(receiverAddress.getHostAddress() + ":" + receiverPort + " datagram received from " + receive.getAddress().getHostAddress() + ":" + receive.getPort());
					MessageHeader receiveMH = MessageHeader.parseHeader(receive.getData()); 
					try {
						receiveMH.parseAttributes(receive.getData());
						if (receiveMH.getType() == MessageHeaderType.BindingRequest) {
							LOGGER.debug(receiverAddress.getHostAddress() + ":" + receiverPort + " Binding Request received from " + receive.getAddress().getHostAddress() + ":" + receive.getPort());
							ChangeRequest cr = (ChangeRequest) receiveMH.getMessageAttribute(MessageAttributeType.ChangeRequest);
							if (cr == null) {
								cr = new ChangeRequest();
							}
							ResponseAddress ra = (ResponseAddress) receiveMH.getMessageAttribute(MessageAttributeType.ResponseAddress);
							ResponsePort rp = (ResponsePort) receiveMH.getMessageAttribute(MessageAttributeType.ResponsePort);
							int targetPort = (rp != null) ? rp.getPort() : receive.getPort();
						
							MessageHeader sendMH = new MessageHeader(MessageHeaderType.BindingResponse);
							sendMH.setTransactionID(receiveMH.getTransactionID());
						
							// Mapped address attribute (RFC 3489) and XOR-Mapped address (RFC 5389/8489)
							MappedAddress ma = new MappedAddress();
							ma.setAddress(new Address(receive.getAddress().getAddress()));
							ma.setPort(receive.getPort());
							sendMH.addMessageAttribute(ma);
							XorMappedAddress xma = new XorMappedAddress(receiveMH.getTransactionID());
							xma.setAddress(new Address(receive.getAddress().getAddress()));
							xma.setPort(receive.getPort());
							sendMH.addMessageAttribute(xma);
							// Changed address (RFC 3489) and Other address (RFC 5780)
							ChangedAddress ca = new ChangedAddress();
							ca.setAddress(new Address(changedPortIPAddress.getAddress()));
							ca.setPort(changedPortIPPort);
							sendMH.addMessageAttribute(ca);
							OtherAddress oa = new OtherAddress();
							oa.setAddress(new Address(changedPortIPAddress.getAddress()));
							oa.setPort(changedPortIPPort);
							sendMH.addMessageAttribute(oa);
							if (cr.isChangePort() && (!cr.isChangeIP())) {
								LOGGER.debug("Change port received in Change Request attribute");
								// Source address / Response origin attribute
								SourceAddress sa = new SourceAddress();
								sa.setAddress(new Address(changedPortAddress.getAddress()));
								sa.setPort(changedPortPort);
								sendMH.addMessageAttribute(sa);
								ResponseOrigin ro = new ResponseOrigin();
								ro.setAddress(new Address(changedPortAddress.getAddress()));
								ro.setPort(changedPortPort);
								sendMH.addMessageAttribute(ro);
								byte[] data = sendMH.getBytes();
								DatagramPacket send = new DatagramPacket(data, data.length);
								if (ra != null) {
									send.setPort(ra.getPort());
									send.setAddress(ra.getAddress().getInetAddress());
								} else {
									send.setPort(targetPort);
									send.setAddress(receive.getAddress());
								}
								changedPort.send(send);
								LOGGER.debug(changedPortAddress.getHostAddress() + ":" + changedPortPort + " send Binding Response to " + send.getAddress().getHostAddress() + ":" + send.getPort());
							} else if ((!cr.isChangePort()) && cr.isChangeIP()) {
								LOGGER.debug("Change ip received in Change Request attribute");
								// Source address / Response origin attribute
								SourceAddress sa = new SourceAddress();
								sa.setAddress(new Address(changedIPAddress.getAddress()));
								sa.setPort(changedIPPort);
								sendMH.addMessageAttribute(sa);
								ResponseOrigin ro = new ResponseOrigin();
								ro.setAddress(new Address(changedIPAddress.getAddress()));
								ro.setPort(changedIPPort);
								sendMH.addMessageAttribute(ro);
								byte[] data = sendMH.getBytes();
								DatagramPacket send = new DatagramPacket(data, data.length);
								if (ra != null) {
									send.setPort(ra.getPort());
									send.setAddress(ra.getAddress().getInetAddress());
								} else {
									send.setPort(targetPort);
									send.setAddress(receive.getAddress());
								}
								changedIP.send(send);
								LOGGER.debug(changedIPAddress.getHostAddress() + ":" + changedIPPort + " send Binding Response to " + send.getAddress().getHostAddress() + ":" + send.getPort());
							} else if ((!cr.isChangePort()) && (!cr.isChangeIP())) {
								LOGGER.debug("Nothing received in Change Request attribute");
								// Source address / Response origin attribute
								SourceAddress sa = new SourceAddress();
								sa.setAddress(new Address(receiverAddress.getAddress()));
								sa.setPort(receiverPort);
								sendMH.addMessageAttribute(sa);
								ResponseOrigin ro = new ResponseOrigin();
								ro.setAddress(new Address(receiverAddress.getAddress()));
								ro.setPort(receiverPort);
								sendMH.addMessageAttribute(ro);
								byte[] data = sendMH.getBytes();
								DatagramPacket send = new DatagramPacket(data, data.length);
								if (ra != null) {
									send.setPort(ra.getPort());
									send.setAddress(ra.getAddress().getInetAddress());
								} else {
									send.setPort(targetPort);
									send.setAddress(receive.getAddress());
								}
								receiverSocket.send(send);
								LOGGER.debug(receiverAddress.getHostAddress() + ":" + receiverPort + " send Binding Response to " + send.getAddress().getHostAddress() + ":" + send.getPort());
							} else if (cr.isChangePort() && cr.isChangeIP()) {
								LOGGER.debug("Change port and ip received in Change Request attribute");
								// Source address / Response origin attribute
								SourceAddress sa = new SourceAddress();
								sa.setAddress(new Address(changedPortIPAddress.getAddress()));
								sa.setPort(changedPortIPPort);
								sendMH.addMessageAttribute(sa);
								ResponseOrigin ro = new ResponseOrigin();
								ro.setAddress(new Address(changedPortIPAddress.getAddress()));
								ro.setPort(changedPortIPPort);
								sendMH.addMessageAttribute(ro);
								byte[] data = sendMH.getBytes();
								DatagramPacket send = new DatagramPacket(data, data.length);
								if (ra != null) {
									send.setPort(ra.getPort());
									send.setAddress(ra.getAddress().getInetAddress());
								} else {
									send.setPort(targetPort);
									send.setAddress(receive.getAddress());
								}
								changedPortIP.send(send);
								LOGGER.debug(changedPortIPAddress.getHostAddress() + ":" + changedPortIPPort + " send Binding Response to " + send.getAddress().getHostAddress() + ":" + send.getPort());
							}
						}
					} catch (UnknownMessageAttributeException umae) {
						LOGGER.debug("Unknown mandatory message attribute: {}", umae.getType());
						// Generate Binding error response
						MessageHeader sendMH = new MessageHeader(MessageHeaderType.BindingErrorResponse);
						sendMH.setTransactionID(receiveMH.getTransactionID());
						
						// Unknown attributes
						UnknownAttribute ua = new UnknownAttribute();
						ua.addAttribute(umae.getType());
						sendMH.addMessageAttribute(ua);
						
						byte[] data = sendMH.getBytes();
						DatagramPacket send = new DatagramPacket(data, data.length);
						send.setPort(receive.getPort());
						send.setAddress(receive.getAddress());
						receiverSocket.send(send);
						LOGGER.debug(receiverAddress.getHostAddress() + ":" + receiverPort + " send Binding Error Response to " + send.getAddress().getHostAddress() + ":" + send.getPort());
					}
				} catch (SocketTimeoutException ioe) {
					// No data for SO_TIMEOUT milliseconds.
				} catch (SocketException se) {
					if (!doRun || receiverSocket.isClosed()) {
						break;
					}
					se.printStackTrace();
				} catch (IOException ioe) {
					ioe.printStackTrace();
				} catch (MessageAttributeParsingException mape) {
					mape.printStackTrace();
				} catch (MessageAttributeException mae) {
					mae.printStackTrace();
				} catch (MessageHeaderParsingException mhpe) {
					mhpe.printStackTrace();
				} catch (UtilityException ue) {
					ue.printStackTrace();
				} catch (ArrayIndexOutOfBoundsException aioobe) {
					aioobe.printStackTrace();
				}
			}
			receiverSocket.close();
		}
	}
	
	/*
	 * To invoke the STUN server two IP addresses and two ports are required.
	 */
	public static void main(String args[]) {
		try {
			if (args.length != 4) {
				System.out.println("usage: java de.javawi.jstun.test.demo.StunServer PORT1 IP1 PORT2 IP2");
				System.out.println();
				System.out.println(" PORT1 - the first port that should be used by the server");
				System.out.println("   IP1 - the first ip address that should be used by the server");
				System.out.println(" PORT2 - the second port that should be used by the server");
				System.out.println("   IP2 - the second ip address that should be used by the server");
				System.exit(0);
			}
			Handler fh = new FileHandler("logging_server.txt");
			fh.setFormatter(new SimpleFormatter());
			java.util.logging.Logger.getLogger("de.javawi.jstun").addHandler(fh);
			java.util.logging.Logger.getLogger("de.javawi.jstun").setLevel(Level.ALL);
			StunServer ss = new StunServer(Integer.parseInt(args[0]), InetAddress.getByName(args[1]),
										   Integer.parseInt(args[2]), InetAddress.getByName(args[3]));
			ss.start();
		} catch (SocketException se) {
			se.printStackTrace();
		} catch (UnknownHostException uhe) {
			uhe.printStackTrace();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}
}