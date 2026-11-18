[![Java CI with Maven](https://github.com/tking/JSTUN/actions/workflows/maven.yml/badge.svg)](https://github.com/tking/JSTUN/actions/workflows/maven.yml) [![Coverage](https://raw.githubusercontent.com/tking/JSTUN/badges/jacoco.svg)](https://github.com/tking/JSTUN/actions/workflows/maven.yml) [![Maven Central](https://img.shields.io/maven-central/v/de.javawi.jstun/jstun.svg)](https://central.sonatype.com/artifact/de.javawi.jstun/jstun)

"JSTUN" - Java Simple Traversal of User Datagram Protocol (UDP) Through Network Address Translation (NAT)
=========================================================================================================

(by Thomas King - king[at]t-king.de)


What is "JSTUN"?
----------------
"JSTUN" is a Java-based STUN (*Session Traversal Utilities for NAT* / *Simple Traversal of User Datagram Protocol (UDP) Through Network Address Translation (NAT)*) implementation. STUN provides a means for applications to discover the presence and behavior of firewalls or NATs between them and the public Internet. Additionally, in the presence of a NAT, STUN can be used by applications to learn the public Internet Protocol (IPv4 / IPv6) address and port assigned to the NAT binding.

"JSTUN" supports both classic STUN (**RFC 3489**) and modern STUN extensions (**RFC 5389 / RFC 8489**, **RFC 5769**, and **RFC 5780**), and includes STUN discovery clients as well as a dual-homed STUN server. "JSTUN" is dual-licensed under the GNU General Public License version 2.0 (GPLv2) and the Apache License version 2.0.


Supported RFCs & Features
-------------------------
* **RFC 5389 / RFC 8489 – Session Traversal Utilities for NAT (STUN)**
  * **Magic Cookie & 96-bit Transaction ID:** `MessageHeader.generateTransactionID()` generates the standard 32-bit Magic Cookie (`0x2112A442`) followed by 96 cryptographically random bits via `SecureRandom` (`hasMagicCookie()` checks for its presence, and `generateRFC3489TransactionID()` remains available for legacy 128-bit transaction IDs).
  * **`XOR-MAPPED-ADDRESS` (`0x0020` / `0x8020`):** Full IPv4 (XOR with Magic Cookie) and IPv6 (128-bit XOR with Magic Cookie + Transaction ID) encoding and decoding via `XorMappedAddress`.
  * **`MESSAGE-INTEGRITY` (`0x0008`) & `MESSAGE-INTEGRITY-SHA256` (`0x001C`):** Complete HMAC-SHA1 (`MessageIntegrity`) and RFC 8489 HMAC-SHA256 (`MessageIntegritySha256`) calculation and verification for both short-term and long-term credentials, plus `USERHASH` (`0x8029`) in `Userhash`.
  * **`FINGERPRINT` (`0x8028`):** CRC-32 XOR `0x5354554e` calculation and verification in `Fingerprint` and `MessageHeader.getBytesWithFingerprint()` to distinguish STUN packets from multiplexed protocols. Automatically appended by `StunServer` and discovery clients (and verified when present) while remaining RFC 3489 backward compatible.
  * **`SOFTWARE` (`0x8022`):** Automatic RFC 5389 §15.10 identification (`JSTUN/<version> (https://github.com/tking/JSTUN)`) via `Software.jstun()` and `JstunVersion` on all client Binding Requests and `StunServer` responses.
  * **Binding Indications (`0x0011`) & `300 Try Alternate` Redirects:** `MessageHeaderType.BindingIndication` (silently accepted without response by `StunServer`) and automatic `AlternateServer` (`0x8023`) redirect handling with loop protection in `NatBehaviorDiscoveryTest`.
  * **Additional RFC 5389 / 8489 Attributes:** `Realm` (`0x0014`) and `Nonce` (`0x0015`).
  * **4-Byte Padding Alignment:** Automatic 4-byte boundary padding when serializing and parsing variable-length attributes and unknown comprehension-optional attributes (`>= 0x8000`).

* **RFC 5780 – NAT Behavior Discovery Using STUN**
  * **Two-Dimensional NAT Classification (`DiscoveryInfo`):**
    * `MappingBehavior`: `DIRECT`, `ENDPOINT_INDEPENDENT`, `ADDRESS_DEPENDENT`, `ADDRESS_AND_PORT_DEPENDENT`
    * `FilteringBehavior`: `ENDPOINT_INDEPENDENT`, `ADDRESS_DEPENDENT`, `ADDRESS_AND_PORT_DEPENDENT`
  * **`NatBehaviorDiscoveryTest`:** Implements the multi-step RFC 5780 procedures for determining NAT Mapping Behavior (Section 4.3, Tests I–III) and NAT Filtering Behavior (Section 4.4, Tests II–III) while maintaining compatibility with classic `DiscoveryInfo` flags.
  * **`MtuDiscoveryTest`:** Implements RFC 5780 Section 4.6 UDP Path MTU probing via binary search and `PADDING` (`0x0026`), supporting `576..9000` bytes (including Ethernet jumbo frames) over IPv4/IPv6 with graceful fallback (`-1`) on legacy RFC 3489 servers.
  * **`HairpinningDiscoveryTest`:** Implements RFC 5780 NAT Hairpinning Behavior discovery by probing a socket's external mapped endpoint from a second local socket.
  * **RFC 5780 `RESPONSE-PORT` Binding Lifetime Probing:** `BindingLifetimeTest.setUseResponsePort(true)` supports RFC 5780 `RESPONSE-PORT` (`0x0027`) probes alongside RFC 3489 `RESPONSE-ADDRESS`.
  * **RFC 5780 Attributes:** `OtherAddress` (`0x802C`, replacing `CHANGED-ADDRESS`), `ResponseOrigin` (`0x802B`, replacing `SOURCE-ADDRESS`), `ResponsePort` (`0x0027`), and `Padding` (`0x0026`).

* **RFC 3489 – Classic STUN & Dual-Stack IPv4/IPv6**
  * Classic cone/symmetric NAT discovery via `DiscoveryTest`, `FastDiscoveryTest`, and `BindingLifetimeTest`, upgraded to transparently accept `XOR-MAPPED-ADDRESS` and `OTHER-ADDRESS` with fallback to `MAPPED-ADDRESS` and `CHANGED-ADDRESS`.
  * IPv4 and IPv6 address family support (thanks to https://github.com/fourjr).
  * Dual-homed `StunServer` supporting standard Binding Requests (with or without `CHANGE-REQUEST`), returning `MAPPED-ADDRESS`, `XOR-MAPPED-ADDRESS`, `SOURCE-ADDRESS`, `RESPONSE-ORIGIN`, `CHANGED-ADDRESS`, `OTHER-ADDRESS`, `SOFTWARE`, and `FINGERPRINT`, honoring `RESPONSE-PORT` and `RESPONSE-ADDRESS`, echoing `PADDING` up to jumbo-frame sizes (`9216` bytes), and returning `ERROR-CODE` (`420`) on unknown mandatory attributes.


How does it work?
-----------------
### Maven Dependency
`JSTUN` is published on Maven Central:
```xml
<dependency>
    <groupId>de.javawi.jstun</groupId>
    <artifactId>jstun</artifactId>
    <version>1.0.1</version>
</dependency>
```

### Client Discovery
To run the classic NAT discovery demo (`DiscoveryTestDemo`), RFC 5780 NAT behavior discovery demo (`NatBehaviorDiscoveryTestDemo`), RFC 5780 Path MTU discovery demo (`MtuDiscoveryTestDemo`), RFC 5780 NAT hairpinning discovery demo (`HairpinningDiscoveryTestDemo`), fast discovery demo (`FastDiscoveryTestDemo`), or UDP binding lifetime discovery demo (`BindingLifetimeTestDemo`):
```bash
# Classic RFC 3489 NAT Discovery
java -cp jstun-1.0.1.jar:slf4j-api-2.0.9.jar:slf4j-jdk14-2.0.9.jar \
  de.javawi.jstun.test.demo.DiscoveryTestDemo

# RFC 5780 NAT Mapping & Filtering Behavior Discovery
java -cp jstun-1.0.1.jar:slf4j-api-2.0.9.jar:slf4j-jdk14-2.0.9.jar \
  de.javawi.jstun.test.demo.NatBehaviorDiscoveryTestDemo

# RFC 5780 UDP Path MTU Discovery (576..9000 bytes, jumbo-frame capable)
java -cp jstun-1.0.1.jar:slf4j-api-2.0.9.jar:slf4j-jdk14-2.0.9.jar \
  de.javawi.jstun.test.demo.MtuDiscoveryTestDemo

# RFC 5780 NAT Hairpinning Behavior Discovery
java -cp jstun-1.0.1.jar:slf4j-api-2.0.9.jar:slf4j-jdk14-2.0.9.jar \
  de.javawi.jstun.test.demo.HairpinningDiscoveryTestDemo

# UDP Binding Lifetime Discovery
java -cp jstun-1.0.1.jar:slf4j-api-2.0.9.jar:slf4j-jdk14-2.0.9.jar \
  de.javawi.jstun.test.demo.BindingLifetimeTestDemo
```
*(Or using the standalone shaded JAR without extra classpath entries: `java -cp jstun-1.0.1-server.jar de.javawi.jstun.test.demo.NatBehaviorDiscoveryTestDemo`. If you build from source with `mvn package`, the JARs are placed in the `target/` directory.)*

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
A `JSTUN`-based STUN server is included and requires a dual-homed machine (two IP addresses and two ports). You can run the self-contained standalone server JAR directly:
```bash
java -jar jstun-1.0.1-server.jar PORT1 IP1 PORT2 IP2
```
Or using the standard library JAR with SLF4J on the classpath:
```bash
java -cp jstun-1.0.1.jar:slf4j-api-2.0.9.jar:slf4j-jdk14-2.0.9.jar \
  de.javawi.jstun.test.demo.StunServer PORT1 IP1 PORT2 IP2
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
* **`Rfc5389And8489Test`:** Tests **RFC 5389 / 8489** `BindingIndication` (`0x0011`) silent server handling, `300 Try Alternate` + `ALTERNATE-SERVER` redirect handling with loop protection, `MessageIntegritySha256` (`0x001C`), and `Userhash` (`0x8029`).
* **`Rfc5769TestVectorsTest`:** Validates byte-for-byte wire compatibility against the official **RFC 5769** STUN test vectors:
  * Section 2.1 Sample Binding Request (`evtj:h6vY`, `STUN test client`, short-term `MESSAGE-INTEGRITY`, `FINGERPRINT`)
  * Section 2.2 IPv4 Binding Response (`192.0.2.1:32853`, `XOR-MAPPED-ADDRESS`, `SOFTWARE`, `MESSAGE-INTEGRITY`, `FINGERPRINT`)
  * Section 2.3 IPv6 Binding Response (`2001:db8:1234:5678:11:2233:4455:6677:32853`)
  * Section 2.4 Long-Term Auth Binding Request (UTF-8 Japanese username `マトリックス`, `example.org`, `TheMatrIX`, `MESSAGE-INTEGRITY`, `FINGERPRINT`)
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
