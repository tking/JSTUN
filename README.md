[![Java CI with Maven](https://github.com/tking/JSTUN/actions/workflows/maven.yml/badge.svg)](https://github.com/tking/JSTUN/actions/workflows/maven.yml) [![Maven Central](https://img.shields.io/maven-central/v/de.javawi.jstun/jstun.svg)](https://central.sonatype.com/artifact/de.javawi.jstun/jstun)

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
  * **`MESSAGE-INTEGRITY` (`0x0008`):** Complete HMAC-SHA1 calculation and verification in `MessageIntegrity` for both short-term credentials (`key`) and long-term credentials (`MD5(username:realm:password)`), including STUN header length adjustment.
  * **`FINGERPRINT` (`0x8028`):** CRC-32 XOR `0x5354554e` calculation and verification in `Fingerprint` to distinguish STUN packets from multiplexed protocols.
  * **Additional RFC 5389 / 8489 Attributes:** `Software` (`0x8022`), `AlternateServer` (`0x8023`), `Realm` (`0x0014`), and `Nonce` (`0x0015`).
  * **4-Byte Padding Alignment:** Automatic 4-byte boundary padding when serializing and parsing variable-length attributes and unknown comprehension-optional attributes (`>= 0x8000`).

* **RFC 5780 – NAT Behavior Discovery Using STUN**
  * **Two-Dimensional NAT Classification (`DiscoveryInfo`):**
    * `MappingBehavior`: `DIRECT`, `ENDPOINT_INDEPENDENT`, `ADDRESS_DEPENDENT`, `ADDRESS_AND_PORT_DEPENDENT`
    * `FilteringBehavior`: `ENDPOINT_INDEPENDENT`, `ADDRESS_DEPENDENT`, `ADDRESS_AND_PORT_DEPENDENT`
  * **`NatBehaviorDiscoveryTest`:** Implements the multi-step RFC 5780 procedures for determining NAT Mapping Behavior (Section 4.3, Tests I–III) and NAT Filtering Behavior (Section 4.4, Tests II–III) while maintaining compatibility with classic `DiscoveryInfo` flags.
  * **RFC 5780 Attributes:** `OtherAddress` (`0x802C`, replacing `CHANGED-ADDRESS`), `ResponseOrigin` (`0x802B`, replacing `SOURCE-ADDRESS`), `ResponsePort` (`0x0027`), and `Padding` (`0x0026`).

* **RFC 3489 – Classic STUN & Dual-Stack IPv4/IPv6**
  * Classic cone/symmetric NAT discovery via `DiscoveryTest`, `FastDiscoveryTest`, and `BindingLifetimeTest`, upgraded to transparently accept `XOR-MAPPED-ADDRESS` and `OTHER-ADDRESS` with fallback to `MAPPED-ADDRESS` and `CHANGED-ADDRESS`.
  * IPv4 and IPv6 address family support (thanks to https://github.com/fourjr).
  * Dual-homed `StunServer` supporting standard Binding Requests (with or without `CHANGE-REQUEST`) and returning `MAPPED-ADDRESS`, `XOR-MAPPED-ADDRESS`, `SOURCE-ADDRESS`, `RESPONSE-ORIGIN`, `CHANGED-ADDRESS`, and `OTHER-ADDRESS` while honoring `RESPONSE-PORT` and `RESPONSE-ADDRESS`.


How does it work?
-----------------
### Maven Dependency
`JSTUN` is published on Maven Central:
```xml
<dependency>
    <groupId>de.javawi.jstun</groupId>
    <artifactId>jstun</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Client Discovery
To run the classic NAT discovery demo across local network interfaces:
```bash
java -cp target/jstun-1.0.0.jar:slf4j-api-2.0.9.jar:slf4j-jdk14-2.0.9.jar \
  de.javawi.jstun.test.demo.DiscoveryTestDemo
```

You can also use `DiscoveryTest`, `FastDiscoveryTest`, `NatBehaviorDiscoveryTest` (for RFC 5780 Mapping & Filtering behavior), or `BindingLifetimeTest` programmatically:
```java
NatBehaviorDiscoveryTest test = new NatBehaviorDiscoveryTest(
    InetAddress.getByName("0.0.0.0"), "jstun.t-king.de", 3478);
DiscoveryInfo info = test.test();
System.out.println(info);
```

### STUN Server
A `JSTUN`-based STUN server is included and requires a dual-homed machine (two IP addresses and two ports). You can run the self-contained standalone server JAR directly:
```bash
java -jar target/jstun-1.0.0-server.jar PORT1 IP1 PORT2 IP2
```
Or using the standard library JAR with SLF4J on the classpath:
```bash
java -cp target/jstun-1.0.0.jar:slf4j-api-2.0.9.jar:slf4j-jdk14-2.0.9.jar \
  de.javawi.jstun.test.demo.StunServer PORT1 IP1 PORT2 IP2
```


Testing
-------
The project uses **JUnit 5** (`org.junit.jupiter`) and can be built and tested via Maven:
```bash
mvn test
```

The test suite (`de.javawi.jstun.AllTests`) includes:
* **`Rfc3489DiscoveryAlgorithmTest`:** Exercises every branch of the **RFC 3489 Section 10.1** NAT and Firewall discovery decision tree for both `DiscoveryTest` and `FastDiscoveryTest` (Blocked UDP, Open Access, Symmetric UDP Firewall, Full Cone NAT, Symmetric NAT, Restricted Cone NAT, Port Restricted Cone NAT, Server Error, and Error 700 incomplete responses).
* **`Rfc5780AttributesAndDiscoveryTest`:** Tests **RFC 5780** attribute serialization/parsing (`OtherAddress`, `ResponseOrigin`, `ResponsePort`, `Padding`) and the full `NatBehaviorDiscoveryTest` algorithm across Section 4.3 Mapping Behavior (`DIRECT`, `ENDPOINT_INDEPENDENT`, `ADDRESS_DEPENDENT`, `ADDRESS_AND_PORT_DEPENDENT`) and Section 4.4 Filtering Behavior (`ENDPOINT_INDEPENDENT`, `ADDRESS_DEPENDENT`, `ADDRESS_AND_PORT_DEPENDENT`).
* **`BindingLifetimeAndStunServerTest`:** Tests the **RFC 3489 Section 10.2** binary-search UDP binding lifetime discovery algorithm (`BindingLifetimeTest`) and the dual-homed `StunServer` across all `CHANGE-REQUEST`, `RESPONSE-PORT`, `RESPONSE-ADDRESS`, and `UNKNOWN-ATTRIBUTES` (`420`) error modes.
* **`Rfc5769TestVectorsTest`:** Validates byte-for-byte wire compatibility against the official **RFC 5769** STUN test vectors:
  * Section 2.2 IPv4 Binding Response (`192.0.2.1:32853`, `XOR-MAPPED-ADDRESS`, `SOFTWARE`, `MESSAGE-INTEGRITY`, `FINGERPRINT`)
  * Section 2.3 IPv6 Binding Response (`2001:db8:1234:5678:11:2233:4455:6677:32853`)
  * 4-byte padding alignment for unaligned comprehension-optional attributes (`>= 0x8000`) and Coturn `ERROR-CODE` responses
* **`StunAttributesAndUtilityTest`:** Tests short-term and long-term `MessageIntegrity` HMAC-SHA1 (including RFC 5769 Section 2.4 UTF-8 Japanese credentials), `Fingerprint` CRC-32 tamper detection, `UnknownAttribute`, `ErrorCode`, `ChangeRequest`, padded string attributes (`Username`, `Password`, `Realm`, `Nonce`, `Software`), IPv4/IPv6 address attributes, and `Utility`.
* **`ICENegotiatorTest`:** Tests **ICE** candidate gathering, priority calculation (`Relayed > PeerReflexive > ServerReflexive > Local`), sorting, and candidate socket handling.
* **`MessageHeaderTest`, `MappedAddressTest`, & `AddressTest`:** Tests STUN header serialization/parsing, Magic Cookie handling, Transaction IDs, and IPv4/IPv6 address utilities.


What do you need?
-----------------
* **Java 17+** (configured as compiler source/target in `pom.xml`, with `Automatic-Module-Name: de.javawi.jstun` for Java module system compatibility).
* **Maven 3+** for building and running the test suite.

If you find a bug or want to contribute enhancements, please open an issue or pull request on [GitHub](https://github.com/tking/JSTUN).
