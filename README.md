[![Java CI with Maven](https://github.com/tking/JSTUN/actions/workflows/maven.yml/badge.svg)](https://github.com/tking/JSTUN/actions/workflows/maven.yml) [![Coverage](https://raw.githubusercontent.com/tking/JSTUN/badges/jacoco.svg)](https://github.com/tking/JSTUN/actions/workflows/maven.yml) [![GitHub Release](https://img.shields.io/github/v/release/tking/JSTUN)](https://github.com/tking/JSTUN/releases/latest) [![Maven Central](https://img.shields.io/maven-central/v/de.javawi.jstun/jstun.svg)](https://central.sonatype.com/artifact/de.javawi.jstun/jstun) [![Java 17+](https://img.shields.io/badge/Java-17%2B-ED8B00?logo=openjdk&logoColor=white)](https://adoptium.net/) [![RFCs](https://img.shields.io/badge/RFC-3489%20%7C%205389%20%7C%205766%20%7C%205769%20%7C%205780%20%7C%207675%20%7C%208489-brightgreen)](#supported-rfcs--features)

"JSTUN" - Java Simple Traversal of User Datagram Protocol (UDP) Through Network Address Translation (NAT)
=========================================================================================================

(by Thomas King - king[at]t-king.de)


What is "JSTUN"?
----------------
"JSTUN" is a Java-based STUN (*Session Traversal Utilities for NAT* / *Simple Traversal of User Datagram Protocol (UDP) Through Network Address Translation (NAT)*) implementation. STUN provides a means for applications to discover the presence and behavior of firewalls or NATs between them and the public Internet. Additionally, in the presence of a NAT, STUN can be used by applications to learn the public Internet Protocol (IPv4 / IPv6) address and port assigned to the NAT binding.

"JSTUN" supports classic STUN (**RFC 3489**), modern STUN (**RFC 5389 / RFC 8489**, **RFC 5769**, **RFC 5780**, and **RFC 7675** Consent Freshness), and TURN relay extensions (**RFC 5766**), including STUN/TURN clients as well as dual-homed STUN and NIO TURN relay servers. "JSTUN" is dual-licensed under the GNU General Public License version 2.0 (GPLv2) and the Apache License version 2.0.


Supported RFCs & Features
-------------------------
* **RFC 5389 / RFC 8489 – Session Traversal Utilities for NAT (STUN)**
  * **Magic Cookie & 96-bit Transaction ID:** `MessageHeader.generateTransactionID()` generates the 32-bit Magic Cookie (`0x2112A442`) followed by 96 cryptographically random bits via `SecureRandom` (`hasMagicCookie()` checks for its presence; `generateRFC3489TransactionID()` remains available for legacy 128-bit IDs).
  * **Address Mapping:** `XOR-MAPPED-ADDRESS` (`0x0020` / `0x8020`) via `XorMappedAddress`, supporting both IPv4 (XOR with Magic Cookie) and IPv6 (128-bit XOR with Magic Cookie + Transaction ID).
  * **Authentication & Integrity:** `MESSAGE-INTEGRITY` (`0x0008`, HMAC-SHA1 via `MessageIntegrity`), `MESSAGE-INTEGRITY-SHA256` (`0x001C`, HMAC-SHA256 via `MessageIntegritySha256`), `USERHASH` (`0x001E` via `Userhash`), `REALM` (`0x0014` via `Realm`), `NONCE` (`0x0015` via `Nonce`), and RFC 4013 `SaslPrep` credential normalization for short-term and long-term credentials.
  * **Packet Multiplexing & Identification:** `FINGERPRINT` (`0x8028`, CRC-32 XOR `0x5354554e` via `Fingerprint` and `MessageHeader.getBytesWithFingerprint()`) and `SOFTWARE` (`0x8022` via `Software.jstun()` and `JstunVersion`, formatted as `JSTUN/<version> (https://github.com/tking/JSTUN)`), automatically appended and verified while preserving RFC 3489 backward compatibility.
  * **Binding Indications & Redirects:** `BindingIndication` (`0x0011` via `MessageHeaderType.BindingIndication`, silently accepted without response by `StunServer`) and `300 Try Alternate` redirects using `ALTERNATE-SERVER` (`0x8023` via `AlternateServer`) with loop protection in `NatBehaviorDiscoveryTest`.
  * **4-Byte Padding Alignment:** Automatic 4-byte boundary padding when serializing and parsing variable-length attributes and unknown comprehension-optional attributes (`>= 0x8000`).

* **RFC 5780 – NAT Behavior Discovery Using STUN**
  * **Two-Dimensional NAT Classification:** `DiscoveryInfo` models `MappingBehavior` (`DIRECT`, `ENDPOINT_INDEPENDENT`, `ADDRESS_DEPENDENT`, `ADDRESS_AND_PORT_DEPENDENT`) and `FilteringBehavior` (`ENDPOINT_INDEPENDENT`, `ADDRESS_DEPENDENT`, `ADDRESS_AND_PORT_DEPENDENT`).
  * **NAT Mapping & Filtering Discovery:** `NatBehaviorDiscoveryTest` implements Section 4.3 Mapping Behavior (Tests I–III) and Section 4.4 Filtering Behavior (Tests II–III) while maintaining classic `DiscoveryInfo` compatibility.
  * **UDP Path MTU Discovery:** `MtuDiscoveryTest` implements Section 4.6 binary-search MTU probing with `PADDING` (`0x0026` via `Padding`), supporting `576..9000` bytes (including Ethernet jumbo frames) over IPv4/IPv6 with graceful `-1` fallback on legacy RFC 3489 servers.
  * **NAT Hairpinning Discovery:** `HairpinningDiscoveryTest` probes a socket's external mapped endpoint from a second local socket to determine hairpinning support.
  * **`RESPONSE-PORT` Binding Lifetime Probing:** `BindingLifetimeTest.setUseResponsePort(true)` probes binding lifetimes using `RESPONSE-PORT` (`0x0027` via `ResponsePort`) alongside classic `RESPONSE-ADDRESS`.
  * **RFC 5780 Attributes:** `OTHER-ADDRESS` (`0x802C` via `OtherAddress`, replacing `CHANGED-ADDRESS`), `RESPONSE-ORIGIN` (`0x802B` via `ResponseOrigin`, replacing `SOURCE-ADDRESS`), `RESPONSE-PORT` (`0x0027` via `ResponsePort`), and `PADDING` (`0x0026` via `Padding`).

* **RFC 5766 – Traversal Using Relays around NAT (TURN)**
  * **TURN Wire Protocol & Framing:** Supports `Allocate` (`0x0003`), `Refresh` (`0x0004`), `Send` (`0x0016`) / `Data` (`0x0017`) indications, `CreatePermission` (`0x0008`), `ChannelBind` (`0x0009`), TURN error codes (`403`, `437`, `440`, `441`, `442`, `486`, `508`), ordered multi-attribute serialization in `MessageHeader`, and binary `ChannelData` (`0x4000..0x7FFF`) framing via `ChannelData`.
  * **TURN Attributes:** `CHANNEL-NUMBER` (`0x000C` via `ChannelNumber`), `LIFETIME` (`0x000D` via `Lifetime`), `XOR-PEER-ADDRESS` (`0x0012` via `XorPeerAddress`), `DATA` (`0x0013` via `Data`), `XOR-RELAYED-ADDRESS` (`0x0016` via `XorRelayedAddress`), `EVEN-PORT` (`0x0018` via `EvenPort`), `REQUESTED-TRANSPORT` (`0x0019` via `RequestedTransport`), `DONT-FRAGMENT` (`0x001A` via `DontFragment`), and `RESERVATION-TOKEN` (`0x0022` via `ReservationToken`).
  * **UDP TURN Client (`TurnClient`) & ICE Integration:** Automatic `401` challenge and `438` stale-nonce retry, `allocate()`, `EVEN-PORT` / `RESERVATION-TOKEN`, `refresh()`, multi-peer `createPermission()`, `channelBind()`, `Send`/`Data` indications, `ChannelData` relaying, and `ICENegotiator.setTurnServer(...)` for gathering `Relayed` candidates.
  * **NIO UDP TURN Server (`TurnServer`):** Single-selector NIO relay server with mandatory HMAC-SHA1 long-term authentication, IP-bound HMAC-SHA256 nonces, 5-tuple allocations with expiry reaper, peer permissions, `ChannelData` relaying, SSRF private-peer blocking (`403` by default), per-user/global quotas (`486` / `508`), and zero-dependency `TurnServerStats`.

* **RFC 7675 – STUN Usage for Consent Freshness**
  * **5-Tuple Consent State Machine (`ConsentSession`):** Enforces explicit peer consent before transmitting application data (`INITIAL` → `ACTIVE` → `EXPIRED` / `REVOKED`), uses single-transmission short-term authenticated STUN Binding Requests with unexposed 96-bit `SecureRandom` transaction IDs, randomizes periodic checks uniformly in `[0.8×, 1.2×]` of the 5-second base interval (4–6 seconds, hard 4-second floor), expires consent after 30 seconds while discarding all outstanding transactions, immediately revokes consent on authenticated `403 Forbidden` or authenticated close alerts while ignoring unauthenticated revocations, prevents ICE credential reuse after consent loss, and supports DiffServ traffic-class marking (`setTrafficClass`).
  * **Peer Responder (`ConsentResponder`):** Full ICE / ICE-lite compatible UDP responder authenticating short-term consent requests, returning signed `BindingResponse` (`XOR-MAPPED-ADDRESS`, `MESSAGE-INTEGRITY`, `FINGERPRINT`) or authenticated `403 Forbidden` immediate revocation responses.

* **RFC 5769 – Test Vectors for Session Traversal Utilities for NAT (STUN)**
  * **Wire-Level Golden Vectors:** Exact byte-for-byte verification of all four official Sections 2.1–2.4 STUN packets (`XOR-MAPPED-ADDRESS` IPv4/IPv6, `PRIORITY` `0x0024`, `SOFTWARE`, `MESSAGE-INTEGRITY`, `FINGERPRINT`, comprehension-optional `ICE-CONTROLLED` `0x8029` skipping, and UTF-8 / RFC 4013 SASLprep long-term credentials) in `Rfc5769TestVectorsTest`.

* **RFC 3489 – Classic STUN (Simple Traversal of UDP Through NATs)**
  * **Classic NAT & Lifetime Discovery:** `DiscoveryTest`, `FastDiscoveryTest`, and `BindingLifetimeTest` implement RFC 3489 Section 10.1/10.2 discovery and transparently prefer `XOR-MAPPED-ADDRESS` and `OTHER-ADDRESS` with fallback to `MAPPED-ADDRESS` (`0x0001`) and `CHANGED-ADDRESS` (`0x0005`).

* **Dual-Homed STUN Server & Dual-Stack Transport**
  * **IPv4 / IPv6 Support:** Full dual-stack address family support across attributes, discovery tests, and server sockets (thanks to [fourjr](https://github.com/fourjr)).
  * **Dual-Homed & Optional Dual-Stack `StunServer`:** Runs in **IPv4-only**, **IPv6-only**, or simultaneous **IPv4 + IPv6 dual-stack** mode in a single server instance (binding 4 sockets per enabled family). Handles standard Binding Requests (with or without `CHANGE-REQUEST`), emits `MAPPED-ADDRESS`, `XOR-MAPPED-ADDRESS`, `SOURCE-ADDRESS`, `RESPONSE-ORIGIN`, `CHANGED-ADDRESS`, `OTHER-ADDRESS`, `SOFTWARE`, and `FINGERPRINT`, honors `RESPONSE-PORT` and `RESPONSE-ADDRESS`, echoes `PADDING` up to jumbo-frame sizes (`9216` bytes), silently ignores `BindingIndication`, and returns `ERROR-CODE` (`420`) with `UNKNOWN-ATTRIBUTES` on unknown mandatory attributes.


How does it work?
-----------------
### Maven Dependency
`JSTUN` is published on Maven Central:
```xml
<dependency>
    <groupId>de.javawi.jstun</groupId>
    <artifactId>jstun</artifactId>
    <version>1.1.1</version>
</dependency>
```

### Client Discovery
To run the classic NAT discovery demo (`DiscoveryTestDemo`), RFC 5780 NAT behavior discovery demo (`NatBehaviorDiscoveryTestDemo`), RFC 5780 Path MTU discovery demo (`MtuDiscoveryTestDemo`), RFC 5780 NAT hairpinning discovery demo (`HairpinningDiscoveryTestDemo`), fast discovery demo (`FastDiscoveryTestDemo`), or UDP binding lifetime discovery demo (`BindingLifetimeTestDemo`):
```bash
# Classic RFC 3489 NAT Discovery
java -cp jstun-1.1.1.jar:slf4j-api-2.0.9.jar:slf4j-jdk14-2.0.9.jar \
  de.javawi.jstun.test.demo.DiscoveryTestDemo

# RFC 5780 NAT Mapping & Filtering Behavior Discovery
java -cp jstun-1.1.1.jar:slf4j-api-2.0.9.jar:slf4j-jdk14-2.0.9.jar \
  de.javawi.jstun.test.demo.NatBehaviorDiscoveryTestDemo

# RFC 5780 UDP Path MTU Discovery (576..9000 bytes, jumbo-frame capable)
java -cp jstun-1.1.1.jar:slf4j-api-2.0.9.jar:slf4j-jdk14-2.0.9.jar \
  de.javawi.jstun.test.demo.MtuDiscoveryTestDemo

# RFC 5780 NAT Hairpinning Behavior Discovery
java -cp jstun-1.1.1.jar:slf4j-api-2.0.9.jar:slf4j-jdk14-2.0.9.jar \
  de.javawi.jstun.test.demo.HairpinningDiscoveryTestDemo

# UDP Binding Lifetime Discovery
java -cp jstun-1.1.1.jar:slf4j-api-2.0.9.jar:slf4j-jdk14-2.0.9.jar \
  de.javawi.jstun.test.demo.BindingLifetimeTestDemo
```
*(Or using the standalone shaded JAR without extra classpath entries: `java -cp jstun-1.1.1-server.jar de.javawi.jstun.test.demo.NatBehaviorDiscoveryTestDemo`. If you build from source with `mvn package`, the JARs are placed in the `target/` directory.)*

You can also use `DiscoveryTest`, `FastDiscoveryTest`, `NatBehaviorDiscoveryTest` (for RFC 5780 Mapping & Filtering behavior), `MtuDiscoveryTest` (for RFC 5780 Path MTU / jumbo-frame probing), or `BindingLifetimeTest` programmatically:
```java
NatBehaviorDiscoveryTest test = new NatBehaviorDiscoveryTest(
    InetAddress.getByName("0.0.0.0"), "jstun.t-king.de", 3478);
DiscoveryInfo info = test.test();
System.out.println(info);

MtuDiscoveryTest mtuTest = new MtuDiscoveryTest(
    InetAddress.getByName("0.0.0.0"), "jstun.t-king.de", 3478);
int discoveredMtu = mtuTest.test(); // probes 576..9000 bytes (supports jumbo frames)

HairpinningDiscoveryTest hairpinTest = new HairpinningDiscoveryTest(
    InetAddress.getByName("0.0.0.0"), "jstun.t-king.de", 3478);
Boolean hairpinningSupported = hairpinTest.test();
```

### STUN Server
A `JSTUN`-based STUN server is included and requires two IP addresses and two ports per enabled address family (dual-homed). It supports **IPv4-only**, **IPv6-only**, or simultaneous **dual-stack (IPv4 + IPv6)** operation from a single process using the standalone shaded JAR:
```bash
# Single-stack (IPv4-only or IPv6-only)
java -jar jstun-1.1.1-server.jar PORT1 IP1 PORT2 IP2

# Dual-stack (IPv4 and IPv6 sharing PORT1/PORT2, e.g. 3478 and 3479)
java -jar jstun-1.1.1-server.jar PORT1 IPv4_1 PORT2 IPv4_2 IPv6_1 IPv6_2

# Dual-stack (IPv4 and IPv6 with independent ports)
java -jar jstun-1.1.1-server.jar PORT1 IPv4_1 PORT2 IPv4_2 PORT1_V6 IPv6_1 PORT2_V6 IPv6_2
```
Or using the standard library JAR with SLF4J on the classpath:
```bash
java -cp jstun-1.1.1.jar:slf4j-api-2.0.9.jar:slf4j-jdk14-2.0.9.jar \
  de.javawi.jstun.test.demo.StunServer PORT1 IP1 PORT2 IP2
```
Server logs rotate automatically (`logging_server.%g.txt`, 10 MB × 5 files) at `INFO` by default, and periodic traffic/error counters are logged every `60` seconds (`-Djstun.stats.interval=0` disables periodic stats). To change the log level (e.g., `FINE` or `ALL`), pass `-Djstun.log.level`:
```bash
java -Djstun.log.level=ALL -Djstun.stats.interval=60 -jar jstun-1.1.1-server.jar PORT1 IP1 PORT2 IP2
```

### TURN Server & Client (RFC 5766)
Run the NIO UDP TURN relay server with one or more `USER:PASS` credentials:
```bash
java -cp jstun-1.1.1-server.jar \
  de.javawi.jstun.turn.TurnServer 3478 0.0.0.0 example.org alice:secret
```
Test relay allocation from the CLI with `TurnClientDemo`:
```bash
java -cp jstun-1.1.1-server.jar \
  de.javawi.jstun.test.demo.TurnClientDemo turn.example.org 3478 alice secret
```

### STUN Consent Freshness (RFC 7675)
Run the self-contained RFC 7675 loopback demo (or pass `<host> <port> <username> <password>` for a live remote peer):
```bash
java -cp jstun-1.1.1-server.jar \
  de.javawi.jstun.test.demo.ConsentFreshnessDemo
```


Testing
-------
The project uses **JUnit 5** (`org.junit.jupiter`) and can be built and tested via Maven:
```bash
mvn test
```

The test suite (`de.javawi.jstun.AllTests`, with JaCoCo coverage reporting in `target/site/jacoco/index.html`) includes:
* **`Rfc3489DiscoveryAlgorithmTest`:** Exercises every branch of the **RFC 3489 Section 10.1** NAT and Firewall discovery decision tree for both `DiscoveryTest` and `FastDiscoveryTest` (Blocked UDP, Open Access, Symmetric UDP Firewall, Full Cone NAT, Symmetric NAT, Restricted Cone NAT, Port Restricted Cone NAT, Server Error, and Error 700 incomplete responses).
* **`Rfc5780AttributesAndDiscoveryTest`:** Tests **RFC 5780** attribute serialization/parsing (`OtherAddress`, `ResponseOrigin`, `ResponsePort`, `Padding`), the full `NatBehaviorDiscoveryTest` algorithm across Section 4.3 Mapping Behavior (`DIRECT`, `ENDPOINT_INDEPENDENT`, `ADDRESS_DEPENDENT`, `ADDRESS_AND_PORT_DEPENDENT`) and Section 4.4 Filtering Behavior (`ENDPOINT_INDEPENDENT`, `ADDRESS_DEPENDENT`, `ADDRESS_AND_PORT_DEPENDENT`), `MtuDiscoveryTest` Section 4.6 MTU probing (`1420`-byte constrained paths, `9000`-byte jumbo frames, IPv6 `::1`, and `420` legacy fallback), and `HairpinningDiscoveryTest` (`TRUE`, `FALSE`, `null`).
* **`BindingLifetimeAndStunServerTest`:** Tests the **RFC 3489 Section 10.2** & **RFC 5780 `RESPONSE-PORT`** binary-search UDP binding lifetime discovery algorithms (`BindingLifetimeTest`) and the dual-homed `StunServer` across all `CHANGE-REQUEST`, `RESPONSE-PORT`, `RESPONSE-ADDRESS`, `SOFTWARE`, `FINGERPRINT` validation/discarding, jumbo `PADDING` echo, and `ERROR-CODE` (`420`) + `UNKNOWN-ATTRIBUTES` error modes.
* **`Rfc5389And8489Test`:** Tests **RFC 5389 / 8489** `BindingIndication` (`0x0011`) silent server handling, `300 Try Alternate` + `ALTERNATE-SERVER` redirect handling with loop protection, `MessageIntegritySha256` (`0x001C`), and `Userhash` (`0x001E`).
* **`Rfc5766WireProtocolTest` & `Rfc5766TurnClientServerTest`:** Tests all **RFC 5766 (TURN)** message types, attributes, repeated `XOR-PEER-ADDRESS` ordering, `MESSAGE-INTEGRITY` + `FINGERPRINT` verification, `ChannelData` framing, and end-to-end `TurnClient` ↔ `TurnServer` ↔ UDP peer relaying (`401`/`438` auth, `403` SSRF filtering, `Send`/`Data` indications, `ChannelBind`/`ChannelData`, `EVEN-PORT` + `RESERVATION-TOKEN`, `486`/`508` quotas, and `ICENegotiator` relayed candidates).
* **`Rfc7675ConsentFreshnessTest`:** Tests **RFC 7675** STUN Consent Freshness (`ConsentSession`, `ConsentResponder`, `ConsentFreshnessDemo`, and `MessageHeader` short-term integrity helpers) across initial blocking of application data, randomized 4–6 s check pacing and 4 s floor enforcement, out-of-order previous transaction responses, replay/spoof/bad-`FINGERPRINT`/bad-`MESSAGE-INTEGRITY` rejection, 30-second expiration and late-response discard, immediate revocation on authenticated `403 Forbidden` or authenticated close (ignoring unauthenticated `403`/close), credential reuse prevention after consent loss, DiffServ marking, and multiplexed UDP loopback scheduling.
* **`Rfc5769TestVectorsTest`:** Validates exact byte-for-byte wire compatibility against all four official **RFC 5769** STUN test vectors plus RFC 4013 `SaslPrep` vectors:
  * Section 2.1 108-byte Binding Request (`evtj:h6vY`, `STUN test client`, `PRIORITY` `0x6e0001ff`, comprehension-optional `ICE-CONTROLLED` `0x8029`, short-term `MESSAGE-INTEGRITY`, `FINGERPRINT`)
  * Section 2.2 80-byte IPv4 Binding Response (`192.0.2.1:32853`, `XOR-MAPPED-ADDRESS`, `SOFTWARE`, `MESSAGE-INTEGRITY`, `FINGERPRINT`)
  * Section 2.3 92-byte IPv6 Binding Response (`2001:db8:1234:5678:11:2233:4455:6677:32853`)
  * Section 2.4 116-byte Long-Term Auth Binding Request (UTF-8 Japanese username `マトリックス`, `example.org`, pre-/post-SASLprep password `The<U+00AD>M<U+00AA>tr<U+2168>` → `TheMatrIX`, `MESSAGE-INTEGRITY`, exact 116-byte parse and serialization round-trip)
  * 4-byte padding alignment for unaligned comprehension-optional attributes (`>= 0x8000`) and Coturn `ERROR-CODE` responses
* **`StunAttributesAndUtilityTest` & `ExceptionsAndEdgeCasesTest`:** Tests short-term and long-term `MessageIntegrity` HMAC-SHA1 (including RFC 5769 Section 2.4 UTF-8 Japanese credentials), `Fingerprint` CRC-32 tamper detection, `UnknownAttribute`, `ErrorCode`, `ChangeRequest`, padded string attributes (`Username`, `Password`, `Realm`, `Nonce`, `Software` 127-char limit), IPv4/IPv6 address attributes, comprehension rules, malformed packets, and `Utility`.
* **`DiscoveryInfoTest` & `DemosAndServerTest`:** Tests `DiscoveryInfo` NAT flags, RFC 5780 behavior/MTU formatting, and demo entrypoints (`DiscoveryTestDemo`, `FastDiscoveryTestDemo`, `NatBehaviorDiscoveryTestDemo`, `MtuDiscoveryTestDemo`, `HairpinningDiscoveryTestDemo`, `BindingLifetimeTestDemo`).
* **`ICENegotiatorTest`:** Tests **ICE** candidate gathering, priority calculation (`Relayed > PeerReflexive > ServerReflexive > Local`), sorting, and candidate socket handling.
* **`MessageHeaderTest`, `MappedAddressTest`, & `AddressTest`:** Tests STUN header serialization/parsing, Magic Cookie handling, Transaction IDs, and IPv4/IPv6 address utilities.


What do you need?
-----------------
* **Java 17+** (configured as compiler source/target in `pom.xml`, with `Automatic-Module-Name: de.javawi.jstun` for Java module system compatibility).
* **Maven 3+** for building and running the test suite.

If you find a bug or want to contribute enhancements, please open an issue or pull request on [GitHub](https://github.com/tking/JSTUN).
