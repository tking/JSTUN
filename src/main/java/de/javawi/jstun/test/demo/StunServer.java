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
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.SimpleFormatter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.javawi.jstun.attribute.ChangeRequest;
import de.javawi.jstun.attribute.ChangedAddress;
import de.javawi.jstun.attribute.ErrorCode;
import de.javawi.jstun.attribute.Fingerprint;
import de.javawi.jstun.attribute.MappedAddress;
import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.attribute.OtherAddress;
import de.javawi.jstun.attribute.Padding;
import de.javawi.jstun.attribute.ResponseAddress;
import de.javawi.jstun.attribute.ResponseOrigin;
import de.javawi.jstun.attribute.ResponsePort;
import de.javawi.jstun.attribute.Software;
import de.javawi.jstun.attribute.SourceAddress;
import de.javawi.jstun.attribute.UnknownAttribute;
import de.javawi.jstun.attribute.UnknownMessageAttributeException;
import de.javawi.jstun.attribute.XorMappedAddress;
import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.util.Address;
import de.javawi.jstun.util.JstunVersion;
import de.javawi.jstun.util.UtilityException;

/*
 * This class implements a STUN server as described in RFC 3489.
 * The server requires a machine that is dual-homed to be functional. 
 */
public class StunServer {
	private static final Logger LOGGER = LoggerFactory.getLogger(StunServer.class);
	/** Receive buffer sized for jumbo frames (9000-byte MTU + headers). */
	private static final int RECEIVE_BUFFER_SIZE = 10240;
	private static final int MAX_ECHO_PACKET_SIZE = 9216;
	static final int LOG_FILE_LIMIT_BYTES = 10 * 1024 * 1024;
	static final int LOG_FILE_COUNT = 5;
	static final String LOG_FILE_PATTERN = "logging_server.%g.txt";
	static final String LOG_LEVEL_PROPERTY = "jstun.log.level";
	static final Level DEFAULT_LOG_LEVEL = Level.INFO;
	static final String STATS_INTERVAL_PROPERTY = "jstun.stats.interval";
	static final long DEFAULT_STATS_INTERVAL_SECONDS = 60L;
	Vector<DatagramSocket> sockets;
	private final Vector<StunServerReceiverThread> receiverThreads = new Vector<StunServerReceiverThread>();
	private final StunServerStats stats = new StunServerStats();
	private ScheduledExecutorService statsScheduler;
	private long statsIntervalSeconds = resolveStatsIntervalSeconds(System.getProperty(STATS_INTERVAL_PROPERTY));
	private volatile boolean doRun;

	/**
	 * Lightweight, zero-dependency server counters exposed for periodic logging and tests.
	 */
	public static final class StunServerStats {
		final AtomicLong packetsReceived = new AtomicLong();
		final AtomicLong bytesReceived = new AtomicLong();
		final AtomicLong bindingRequests = new AtomicLong();
		final AtomicLong bindingIndications = new AtomicLong();
		final AtomicLong changeRequests = new AtomicLong();
		final AtomicLong paddingRequests = new AtomicLong();
		final AtomicLong responsePortRequests = new AtomicLong();
		final AtomicLong responseAddressRequests = new AtomicLong();
		final AtomicLong bindingResponsesSent = new AtomicLong();
		final AtomicLong bindingErrorsSent = new AtomicLong();
		final AtomicLong bytesSent = new AtomicLong();
		final AtomicLong droppedInvalidFingerprint = new AtomicLong();
		final AtomicLong droppedParseError = new AtomicLong();
		final AtomicLong droppedRuntimeError = new AtomicLong();

		public long getPacketsReceived() { return packetsReceived.get(); }
		public long getBytesReceived() { return bytesReceived.get(); }
		public long getBindingRequests() { return bindingRequests.get(); }
		public long getBindingIndications() { return bindingIndications.get(); }
		public long getChangeRequests() { return changeRequests.get(); }
		public long getPaddingRequests() { return paddingRequests.get(); }
		public long getResponsePortRequests() { return responsePortRequests.get(); }
		public long getResponseAddressRequests() { return responseAddressRequests.get(); }
		public long getBindingResponsesSent() { return bindingResponsesSent.get(); }
		public long getBindingErrorsSent() { return bindingErrorsSent.get(); }
		public long getBytesSent() { return bytesSent.get(); }
		public long getDroppedInvalidFingerprint() { return droppedInvalidFingerprint.get(); }
		public long getDroppedParseError() { return droppedParseError.get(); }
		public long getDroppedRuntimeError() { return droppedRuntimeError.get(); }

		public String formatSummary() {
			return "packetsIn=" + packetsReceived.get()
					+ " bytesIn=" + bytesReceived.get()
					+ " bindingReq=" + bindingRequests.get()
					+ " bindingInd=" + bindingIndications.get()
					+ " changeReq=" + changeRequests.get()
					+ " paddingReq=" + paddingRequests.get()
					+ " respPortReq=" + responsePortRequests.get()
					+ " respAddrReq=" + responseAddressRequests.get()
					+ " responsesOut=" + bindingResponsesSent.get()
					+ " errors420=" + bindingErrorsSent.get()
					+ " bytesOut=" + bytesSent.get()
					+ " droppedBadFp=" + droppedInvalidFingerprint.get()
					+ " droppedParse=" + droppedParseError.get()
					+ " droppedRuntime=" + droppedRuntimeError.get();
		}
	}

	public StunServerStats getStats() {
		return stats;
	}

	public void setStatsIntervalSeconds(long statsIntervalSeconds) {
		this.statsIntervalSeconds = statsIntervalSeconds;
	}

	Vector<StunServerReceiverThread> getReceiverThreads() {
		return receiverThreads;
	}
	
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
			socket.setReceiveBufferSize(65536);
			socket.setSendBufferSize(65536);
			StunServerReceiverThread ssrt = new StunServerReceiverThread(socket);
			receiverThreads.add(ssrt);
			ssrt.start();
			LOGGER.info("STUN Server receiver thread '{}' started on {}:{}.",
					ssrt.getName(), socket.getLocalAddress().getHostAddress(), socket.getLocalPort());
		}
		if (statsIntervalSeconds > 0) {
			statsScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
				Thread t = new Thread(r, "stun-stats-reporter");
				t.setDaemon(true);
				return t;
			});
			statsScheduler.scheduleAtFixedRate(
					() -> LOGGER.info("STUN Server stats: {}", stats.formatSummary()),
					statsIntervalSeconds, statsIntervalSeconds, TimeUnit.SECONDS);
		}
	}

	public void stop() {
		if (!doRun && (statsScheduler == null || statsScheduler.isShutdown())) {
			return;
		}
		doRun = false;
		if (statsScheduler != null) {
			statsScheduler.shutdownNow();
		}
		final long start = System.currentTimeMillis();
		for ( DatagramSocket socket : sockets ) {
			socket.close();
			// Wait for a wile to allow sockets to disconnect gracefully.
			while ( !socket.isClosed() && System.currentTimeMillis() - start < 7000 ) {
				try {
					Thread.sleep( 50 );
				} catch ( InterruptedException e ) {
					Thread.currentThread().interrupt();
					LOGGER.warn("Interrupted while waiting for STUN server socket to close.", e);
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
					LOGGER.warn("Interrupted while joining STUN server receiver thread.", e);
				}
			}
		}
		LOGGER.info("STUN Server stopped. Final stats: {}", stats.formatSummary());
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
		
		private final ChangedAddress ca;
		private final OtherAddress oa;
		private final SourceAddress saNone;
		private final ResponseOrigin roNone;
		private final SourceAddress saPort;
		private final ResponseOrigin roPort;
		private final SourceAddress saIP;
		private final ResponseOrigin roIP;
		private final SourceAddress saPortIP;
		private final ResponseOrigin roPortIP;
		// RFC 5389 Section 15.10: identify the server software in all responses.
		private final Software software = Software.jstun();

		StunServerReceiverThread(DatagramSocket datagramSocket) {
			super("stun-recv-" + datagramSocket.getLocalAddress().getHostAddress() + ":" + datagramSocket.getLocalPort());
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

			try {
				this.ca = new ChangedAddress();
				this.ca.setAddress(new Address(changedPortIPAddress.getAddress()));
				this.ca.setPort(changedPortIPPort);

				this.oa = new OtherAddress();
				this.oa.setAddress(new Address(changedPortIPAddress.getAddress()));
				this.oa.setPort(changedPortIPPort);

				this.saNone = new SourceAddress();
				this.saNone.setAddress(new Address(receiverAddress.getAddress()));
				this.saNone.setPort(receiverPort);
				this.roNone = new ResponseOrigin();
				this.roNone.setAddress(new Address(receiverAddress.getAddress()));
				this.roNone.setPort(receiverPort);

				this.saPort = new SourceAddress();
				this.saPort.setAddress(new Address(changedPortAddress.getAddress()));
				this.saPort.setPort(changedPortPort);
				this.roPort = new ResponseOrigin();
				this.roPort.setAddress(new Address(changedPortAddress.getAddress()));
				this.roPort.setPort(changedPortPort);

				this.saIP = new SourceAddress();
				this.saIP.setAddress(new Address(changedIPAddress.getAddress()));
				this.saIP.setPort(changedIPPort);
				this.roIP = new ResponseOrigin();
				this.roIP.setAddress(new Address(changedIPAddress.getAddress()));
				this.roIP.setPort(changedIPPort);

				this.saPortIP = new SourceAddress();
				this.saPortIP.setAddress(new Address(changedPortIPAddress.getAddress()));
				this.saPortIP.setPort(changedPortIPPort);
				this.roPortIP = new ResponseOrigin();
				this.roPortIP.setAddress(new Address(changedPortIPAddress.getAddress()));
				this.roPortIP.setPort(changedPortIPPort);
			} catch (UtilityException | MessageAttributeException e) {
				throw new RuntimeException("Failed to initialize static STUN server attributes", e);
			}
		}
		
		public void run() {
			byte[] receiveBuffer = new byte[RECEIVE_BUFFER_SIZE];
			DatagramPacket receive = new DatagramPacket(receiveBuffer, receiveBuffer.length);
			while (doRun) {
				String sourceEndpoint = "unknown";
				int packetLen = -1;
				try {
					receive.setData(receiveBuffer, 0, receiveBuffer.length);
					receiverSocket.receive(receive);
					sourceEndpoint = receive.getAddress().getHostAddress() + ":" + receive.getPort();
					packetLen = receive.getLength();
					stats.packetsReceived.incrementAndGet();
					stats.bytesReceived.addAndGet(packetLen);
					LOGGER.debug("{}:{} datagram received from {} ({} bytes)", receiverAddress.getHostAddress(), receiverPort, sourceEndpoint, packetLen);
					byte[] packetData = new byte[packetLen];
					System.arraycopy(receiveBuffer, 0, packetData, 0, packetData.length);
					MessageHeader receiveMH = MessageHeader.parseHeader(packetData); 
					try {
						receiveMH.parseAttributes(packetData);
						if (receiveMH.getMessageAttribute(MessageAttributeType.Fingerprint) != null
								&& !Fingerprint.verify(packetData)) {
							stats.droppedInvalidFingerprint.incrementAndGet();
							LOGGER.warn("Invalid FINGERPRINT attribute in STUN packet ({} bytes) from {}; discarding packet.",
									packetLen, sourceEndpoint);
							continue;
						}
						if (receiveMH.getType() == MessageHeaderType.BindingIndication) {
							stats.bindingIndications.incrementAndGet();
							LOGGER.debug("{}:{} Binding Indication received from {}; no response sent per RFC 5389.",
									receiverAddress.getHostAddress(), receiverPort, sourceEndpoint);
						} else if (receiveMH.getType() == MessageHeaderType.BindingRequest) {
							stats.bindingRequests.incrementAndGet();
							LOGGER.debug("{}:{} Binding Request received from {}", receiverAddress.getHostAddress(), receiverPort, sourceEndpoint);
							ChangeRequest cr = (ChangeRequest) receiveMH.getMessageAttribute(MessageAttributeType.ChangeRequest);
							if (cr == null) {
								cr = new ChangeRequest();
							} else if (cr.isChangeIP() || cr.isChangePort()) {
								stats.changeRequests.incrementAndGet();
							}
							ResponseAddress ra = (ResponseAddress) receiveMH.getMessageAttribute(MessageAttributeType.ResponseAddress);
							ResponsePort rp = (ResponsePort) receiveMH.getMessageAttribute(MessageAttributeType.ResponsePort);
							if (ra != null) {
								stats.responseAddressRequests.incrementAndGet();
							}
							if (rp != null) {
								stats.responsePortRequests.incrementAndGet();
							}
							int targetPort = (rp != null) ? rp.getPort() : receive.getPort();
						
							MessageHeader sendMH = new MessageHeader(MessageHeaderType.BindingResponse);
							sendMH.setTransactionID(receiveMH.getTransactionID());
						
							// Mapped address attribute (RFC 3489) and XOR-Mapped address (RFC 5389/8489)
							Address clientAddress = new Address(receive.getAddress().getAddress());
							int clientPort = receive.getPort();

							MappedAddress ma = new MappedAddress();
							ma.setAddress(clientAddress);
							ma.setPort(clientPort);
							sendMH.addMessageAttribute(ma);

							XorMappedAddress xma = new XorMappedAddress(receiveMH.getTransactionID());
							xma.setAddress(clientAddress);
							xma.setPort(clientPort);
							sendMH.addMessageAttribute(xma);

							// Changed address (RFC 3489) and Other address (RFC 5780)
							sendMH.addMessageAttribute(ca);
							sendMH.addMessageAttribute(oa);
							sendMH.addMessageAttribute(software);

							final DatagramSocket sendSocket;
							final InetAddress sendAddr;
							final int sendPort;
							if (cr.isChangePort() && (!cr.isChangeIP())) {
								LOGGER.debug("Change port received in Change Request attribute");
								sendMH.addMessageAttribute(saPort);
								sendMH.addMessageAttribute(roPort);
								sendSocket = changedPort;
								sendAddr = changedPortAddress;
								sendPort = changedPortPort;
							} else if ((!cr.isChangePort()) && cr.isChangeIP()) {
								LOGGER.debug("Change ip received in Change Request attribute");
								sendMH.addMessageAttribute(saIP);
								sendMH.addMessageAttribute(roIP);
								sendSocket = changedIP;
								sendAddr = changedIPAddress;
								sendPort = changedIPPort;
							} else if ((!cr.isChangePort()) && (!cr.isChangeIP())) {
								LOGGER.debug("Nothing received in Change Request attribute");
								sendMH.addMessageAttribute(saNone);
								sendMH.addMessageAttribute(roNone);
								sendSocket = receiverSocket;
								sendAddr = receiverAddress;
								sendPort = receiverPort;
							} else {
								LOGGER.debug("Change port and ip received in Change Request attribute");
								sendMH.addMessageAttribute(saPortIP);
								sendMH.addMessageAttribute(roPortIP);
								sendSocket = changedPortIP;
								sendAddr = changedPortIPAddress;
								sendPort = changedPortIPPort;
							}

							Padding reqPadding = (Padding) receiveMH.getMessageAttribute(MessageAttributeType.Padding);
							if (reqPadding != null) {
								stats.paddingRequests.incrementAndGet();
								// RFC 5780 §4.6: echo PADDING up to the incoming request size (capped, zero amplification)
								int baseLenWithFingerprint = sendMH.getBytesWithFingerprint().length;
								int targetSize = Math.min(packetData.length, MAX_ECHO_PACKET_SIZE);
								int rawEchoPad = targetSize - baseLenWithFingerprint - 4;
								if (rawEchoPad >= 0) {
									int alignedPad = (rawEchoPad / 4) * 4;
									sendMH.addMessageAttribute(new Padding(alignedPad));
								}
							}

							byte[] data = sendMH.getBytesWithFingerprint();
							DatagramPacket send = new DatagramPacket(data, data.length);
							if (ra != null) {
								send.setPort(ra.getPort());
								send.setAddress(ra.getAddress().getInetAddress());
							} else {
								send.setPort(targetPort);
								send.setAddress(receive.getAddress());
							}
							sendSocket.send(send);
							stats.bindingResponsesSent.incrementAndGet();
							stats.bytesSent.addAndGet(data.length);
							LOGGER.debug("{}:{} send Binding Response ({} bytes) to {}:{}",
									sendAddr.getHostAddress(), sendPort, data.length,
									send.getAddress().getHostAddress(), send.getPort());
						}
					} catch (UnknownMessageAttributeException umae) {
						LOGGER.warn("Unknown mandatory message attribute {} received from {} ({} bytes); sending Binding Error Response.",
								umae.getType(), sourceEndpoint, packetLen);
						// Generate Binding error response
						MessageHeader sendMH = new MessageHeader(MessageHeaderType.BindingErrorResponse);
						sendMH.setTransactionID(receiveMH.getTransactionID());
						
						// Error code 420 (Unknown Attribute) per RFC 3489 §11.2.9 / RFC 5389 §7.3.1
						ErrorCode ec = new ErrorCode();
						ec.setResponseCode(420);
						sendMH.addMessageAttribute(ec);

						// Unknown attributes
						UnknownAttribute ua = new UnknownAttribute();
						ua.addAttribute(umae.getType());
						sendMH.addMessageAttribute(ua);
						sendMH.addMessageAttribute(software);
						
						byte[] data = sendMH.getBytesWithFingerprint();
						DatagramPacket send = new DatagramPacket(data, data.length);
						send.setPort(receive.getPort());
						send.setAddress(receive.getAddress());
						receiverSocket.send(send);
						stats.bindingErrorsSent.incrementAndGet();
						stats.bytesSent.addAndGet(data.length);
						LOGGER.debug("{}:{} send Binding Error Response ({} bytes) to {}:{}",
								receiverAddress.getHostAddress(), receiverPort, data.length,
								send.getAddress().getHostAddress(), send.getPort());
					}
				} catch (SocketTimeoutException ioe) {
					// No data for SO_TIMEOUT milliseconds.
				} catch (SocketException se) {
					if (!doRun || receiverSocket.isClosed()) {
						break;
					}
					LOGGER.error("SocketException in STUN server receiver thread: {}", se.getMessage(), se);
				} catch (IOException ioe) {
					LOGGER.error("IOException in STUN server receiver thread: {}", ioe.getMessage(), ioe);
				} catch (MessageAttributeParsingException mape) {
					stats.droppedParseError.incrementAndGet();
					LOGGER.warn("MessageAttributeParsingException while parsing STUN packet ({} bytes) from {}: {}",
							packetLen, sourceEndpoint, mape.getMessage());
				} catch (MessageAttributeException mae) {
					stats.droppedParseError.incrementAndGet();
					LOGGER.warn("MessageAttributeException while processing STUN packet ({} bytes) from {}: {}",
							packetLen, sourceEndpoint, mae.getMessage());
				} catch (MessageHeaderParsingException mhpe) {
					stats.droppedParseError.incrementAndGet();
					LOGGER.warn("MessageHeaderParsingException while parsing STUN packet ({} bytes) from {}: {}",
							packetLen, sourceEndpoint, mhpe.getMessage());
				} catch (UtilityException ue) {
					stats.droppedParseError.incrementAndGet();
					LOGGER.warn("UtilityException while processing STUN packet ({} bytes) from {}: {}",
							packetLen, sourceEndpoint, ue.getMessage());
				} catch (ArrayIndexOutOfBoundsException aioobe) {
					stats.droppedParseError.incrementAndGet();
					LOGGER.warn("Malformed STUN packet ({} bytes) from {} caused ArrayIndexOutOfBoundsException: {}",
							packetLen, sourceEndpoint, aioobe.getMessage());
				} catch (RuntimeException re) {
					stats.droppedRuntimeError.incrementAndGet();
					LOGGER.warn("Unexpected RuntimeException while processing STUN packet ({} bytes) from {}: {}",
							packetLen, sourceEndpoint, re.getMessage(), re);
				}
			}
			receiverSocket.close();
		}
	}
	
	static long resolveStatsIntervalSeconds(String intervalValue) {
		if (intervalValue == null || intervalValue.trim().isEmpty()) {
			return DEFAULT_STATS_INTERVAL_SECONDS;
		}
		try {
			return Long.parseLong(intervalValue.trim());
		} catch (NumberFormatException e) {
			LOGGER.warn("Invalid {} value '{}'; falling back to {}s.",
					STATS_INTERVAL_PROPERTY, intervalValue, DEFAULT_STATS_INTERVAL_SECONDS);
			return DEFAULT_STATS_INTERVAL_SECONDS;
		}
	}

	static Level resolveLogLevel(String levelName) {
		if (levelName == null || levelName.trim().isEmpty()) {
			return DEFAULT_LOG_LEVEL;
		}
		try {
			return Level.parse(levelName.trim().toUpperCase(java.util.Locale.ROOT));
		} catch (IllegalArgumentException e) {
			LOGGER.warn("Invalid {} value '{}'; falling back to {}.", LOG_LEVEL_PROPERTY, levelName, DEFAULT_LOG_LEVEL);
			return DEFAULT_LOG_LEVEL;
		}
	}

	static FileHandler createLogFileHandler(String pattern) throws IOException {
		return createLogFileHandler(pattern, DEFAULT_LOG_LEVEL);
	}

	static FileHandler createLogFileHandler(String pattern, Level level) throws IOException {
		FileHandler fh = new FileHandler(pattern, LOG_FILE_LIMIT_BYTES, LOG_FILE_COUNT, true);
		fh.setFormatter(new SimpleFormatter());
		fh.setLevel(level);
		return fh;
	}

	static Level configureLogging(java.util.logging.Logger julLogger, Handler fileHandler, String levelName) {
		Level logLevel = resolveLogLevel(levelName);
		fileHandler.setLevel(logLevel);
		julLogger.addHandler(fileHandler);
		julLogger.setLevel(logLevel);
		java.util.logging.Logger rootLogger = java.util.logging.Logger.getLogger("");
		for (Handler h : rootLogger.getHandlers()) {
			h.setLevel(logLevel);
		}
		return logLevel;
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
			String configuredLevel = System.getProperty(LOG_LEVEL_PROPERTY);
			Level logLevel = resolveLogLevel(configuredLevel);
			Handler fh = createLogFileHandler(LOG_FILE_PATTERN, logLevel);
			configureLogging(java.util.logging.Logger.getLogger("de.javawi.jstun"), fh, configuredLevel);
			StunServer ss = new StunServer(Integer.parseInt(args[0]), InetAddress.getByName(args[1]),
										   Integer.parseInt(args[2]), InetAddress.getByName(args[3]));
			Runtime.getRuntime().addShutdownHook(new Thread(() -> {
				LOGGER.info("Shutdown signal received; stopping STUN server...");
				ss.stop();
			}, "stun-shutdown-hook"));
			LOGGER.info("Starting {}", JstunVersion.SOFTWARE);
			ss.start();
		} catch (SocketException se) {
			LOGGER.error("SocketException while starting STUN server: {}", se.getMessage(), se);
		} catch (UnknownHostException uhe) {
			LOGGER.error("UnknownHostException while starting STUN server: {}", uhe.getMessage(), uhe);
		} catch (IOException ioe) {
			LOGGER.error("IOException while starting STUN server: {}", ioe.getMessage(), ioe);
		}
	}
}