"JSTUN" - Java Simple Traversal of User Datagram Protocol (UDP) Through Network Address Translation (NAT)
=========================================================================================================

(by Thomas King - king[at]t-king.de - Official website: http://jstun.javawi.de) 
 

What is "JSTUN"?
----------------
"JSTUN" is a Java-based STUN (Simple Traversal of User Datagram Protocol (UDP) Through Network Address Translation (NAT)) implementation. STUN provides a mean for applications to discover the presence and type of firewalls or NATs between them and the public internet. Additionally, in presence of a NAT STUN can be used by applications to learn the public Internet Protocol (IP) address assigned to the NAT.

So far, most of the message headers and attributes as standardized in RFC 3489 are part of "JSTUN". The current "JSTUN" version also includes a STUN client and a STUN server. "JSTUN" is dual-licensed under GNU General Public License iversion 2.0 and Apache License version 2.0.


How does it work?
-----------------
STUN is described in RFC 3489. A STUN server is running on jstun.javawi.de:3478.

Just invoke "java -cp jstun-0.7.3.jar:slf4j-api-1.5.6.jar:slf4j-jdk14-1.5.6.jar de.javawi.jstun.test.demo.DiscoveryTestDemo" or use the de.javawi.jstun.test.demo.DiscoveryTest and de.javawi.jstun.test.demo.BindingLifetimeTest classes in order to start the STUN client.

A "JSTUN"-based STUN server is also available. Just try it (assuming you own a dual-homed machine): java -cp jstun-0.7.3.jar:slf4j-api-1.5.6.jar:slf4j-jdk14-1.5.6.jar de.javawi.jstun.test.demo. StunServer PORT1 IP1 PORT2 IP2.
 

What about RFC 5389?
--------------------
I am looking for a way to enhance the current "JSTUN" implementation to support the new Session Traversal Utilities for NAT (STUN) protocol as described in RFC 5389. If you are interested in supporting this effort with code or money please drop me a mail (king[at]t-king.de).
 

Limits?
-------
Due to the lack of fully RFC compliant STUN servers I could not test the shared secret request / response functionality. Additionally, the message attribute username, password and message integrity are not tested for the same reason. The implementation of the message attribute message integrity is not completed, because I see no reason to add a cryptographic library as long as no public available STUN server supports message integrity.

The reality is not as dark as it might seem after reading the previous section. All tested STUN servers provided a minimal set of functionality that is required to discover firewalls and NATs.

If you found a bug or if you want to implement enhancements or additional functionalities please do not hesitate to contact me by email. A CVS account can be provided if needed.

 
What do you need?
-----------------
A Java 6 compliant Java Runtime Environment is required by "JSTUN".
