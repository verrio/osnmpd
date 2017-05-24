osnmpd Agent
============

## Overview

osnmpd is a lightweight SNMPv3 agent, with focus on low memory footprint and simplicity.  The MIB is loaded as a set of shared objects; the included modules provide statistics on memory, CPU, network usage and more.  A limited set of SNMP “set” actions are supported.  Trap and Inform notifications can be handed to the agent via a message queue.  A fixed set of security profiles are available, using the user-based security model (USM).

This document gives an overview on how to compile, setup and use the agent.

## Installation

Installation uses the standard autotools commands:

```sh
autoreconf -i
./configure
make
make install
etc.
```

Dependencies:
- GNU build tools
- Linux kernel 3.x or higher (for IP statistics and non-POSIX compliant message queue use)
- OpenSSL (libcrypto)
- libconfig
- pcscd (if smartcard support is enabled)
- libsensors (if sensor module is enabled)
- nut/upsd (if UPS module is enabled)

## Configuration

The SNMP agent stores its configuration in a file located at `/etc/snmp/snmpd.conf`

Configuration changes emitted via the control interface overwrite this file.

## Use

Start and use the SNMP agent like any normal daemon process

```sh
/etc/init.d/osnmpd {start,stop,restart}
```

The agent uses the UDP transport layer, binding on port 161 by default.  The maximum PDU size is restricted to 1280 to avoid fragmentation on the network layer.  Some corporate networks like to block ICMP and/or fragmented packets, which leads to all kinds of frustrating troubleshooting sessions.  There is a special place in hell for people who enforce such firewall rules, but until justice is served, fragmentation should be avoided.

## Security

SNMP has historically a bad reputation when it comes to security.  The community plain-text password which is unfortunately still omnipresent doesn't really provide any serious level of authenticity or privacy.  The osnmp agent implements the user-based security model (USM), which is the first and default security model introduced with the third revision of the SNMP protocol.  Four user profiles are available:

- public user: A user which can only access the system group of the SNMPv2-MIB, useful for device discovery.
- read-only user: User with read-only access rights
- read-write user: User with write access, though not for security related settings
- admin user: User with unrestricted read and write access

Each user has a set of keys derived from a user-provided authentication and privacy password.  Alternatively, it is possible to preprovision the derived keys in the agent configuration, thereby skipping the key derivation process.  The keys can remotely be renewed using a Diffie-Hellman key exchange procedure as described in RFC 2786.  The agent uses the USM variant with modern cryptoprimitives (CFB128-AES-256 encryption with an HMAC192-SHA-256 authentication tag).  No non-standard key extensions are required, since the hashing algorithm generates 32-byte output.  A lot of clients seem to lack support for these newer ciphers however.  Legacy but more common primitives (AES-128/SHA-1) can be enabled in the build configuration.

Security models other than USM are currently not available (so no TLS or Kerberos authentication).  I personally loathe the complexity involved with PKIX path building and X.509 certificate validation, and I believe I'll never completely understand how it actually all ties together.  A newer security model piggybacking on top of SSH (RFC 5592) sounds very tempting, but I haven't found a single client that supports it properly, so I'll leave it out for now.

The agent needs not run as root;  once the socket has been bound, it can drop privileges to the configured user.  Mind though that a lot of the MIB attributes require elevated access rights and capabilities (e.g. the `CAP_SYS_TIME` capability for changing the system time).

## Notifications

The agent supports confirmed notifications (“traps”) and unconfirmed notifications (“informs”).  A single UDP destination can be configured to receive these.  Notifications can be dispatched to the agent via a system-wide available message queue.  The agent expects the notifications in a simple ASN.1 BER marshalled format defined in `message-format.asn1`.  Any process which has access to the message queue can dispatch traps.

## Management

The agent exposes a UNIX socket on which basic management actions can be performed: changing the user configuration, changing the access to the agent, etc.  The agent will overwrite its own configuration file after dispatching commands to this socket, so make sure to grant the agent write-access to its configuration directory (`/etc/snmp` by default).

## MIB modules

The MIB exposed by the agent consists of modules which are loaded from a set of shared objects.  Modules can be left out in the build configuration if unneeded.  External modules can be plugged in by dropping the shared object in the configured library directory.  An example dump of available attributes can be found in the file `example-tree`.

The following modules are included:

#### System module

This module contains all attributes relating to the system on which the agent is running.  This includes CPU, file system and process statistics.  A subset of the following MIBs are implemented:

- RFC1213-MIB
- HOST-RESOURCES-MIB
- NETWORK-SERVICES-MIB
- UCD-SNMP-MIB

#### Agent module

This module contains all attributes relating to the SNMP agent itself: counters, USM and VACM attributes, etc.  A subset of the following MIBs is available:

- SNMP-FRAMEWORK-MIB
- SNMP-MPD-MIB
- SNMP-NOTIFICATION-MIB
- SNMP-TARGET-MIB
- SNMP-USER-BASED-SM-MIB
- SNMP-USM-DH-OBJECTS-MIB
- SNMPv2-MIB
- SNMP-VIEW-BASED-ACM-MIB

#### IP module

This module contains all IP networking related attributes: configured addresses, ICMP/UDP/TCP/SCTP statistics, etc.  A subset of the following MIBs is available:

- IF-INVERTED-STACK-MIB
- IF-MIB
- IP-MIB
- TCP-MIB
- UDP-MIB
- SCTP-MIB

#### Location module

This modules contains attributes relating to the physical location of the device, supplied by a gpsd daemon process.  The following MIBs relate to this module:

- GPS-MIB

This module requires a running gpsd daemon.

#### Power module

This module contains power-management related attributes.  This includes the following MIBs:

- BATTERY-MIB
- UPS-MIB

This module requires a running upsd daemon.

#### Sensors module

Module containing sensor-related statistics.  Currently this is limited to the sensor data exposed via the libsensors library.  The following MIBs relate to this module:

- ENTITY-SENSORS-MIB

This module requires libsensors support.

#### Subagent module

This module allows for delegating requests for a MIB subtree to an external process (in my case: an external Java application) using a UNIX socket.

## FAQ

#### Using SNMP in the present time!?  What kind of man are you?

I admit, SNMP has it quirky sides.  In particular, the lack of table joins and other query operations is sometimes frustrating.  Still, being a non-propietary standard makes up for that.  Just about any device on my network, doesn't matter how crappy the firmware, has some basic SNMP support.  Traps aren't as fancy as pub-sub based protocols, but for basic network monitoring they still seem to do the job.  The high-end networking equipment seems to move on to more capable proprietary standards, but I'd wager for the low-end SNMP will stick around for some time to come.

#### How safe is USM really?

I'm not qualified to answer that, but it has been around for more than 15 years now, and the only security risk I've found on the web is related to the engine and time discovery (which could be spoofed, thereby repeating packets with the same IV).  A good client could avoid that attack though by using a strong RNG for the random part of the IV, and by incrementing the message ID on every request.

I like to believe that “no security incidents found” means that it's a safe standard, but it most likely means that nobody really bothered to look into it.  Especially the key derivation described in the RFC feels kind of fruity, but again I'm not in a position to judge that.  If you do believe there are security risks involved, please let me know!  I'm more than happy to learn more on the matter.

#### Any plans on supporting other transport layers (TCP/SSH/TLS)?

Currently UDP seems the only SNMP transport that works with all clients.  The only drawback is the limited PDU size, but I haven't bumped into a attribute too large to fit in a PDU yet.  I don't know if wiring a packet-based application protocol on top of a stream-based transport layer makes all that much sense, but Jedem das Seine.

#### Why not use Net-SNMP like the rest?

In pretty much all cases, that would be the sane choice.  I had some specific goals in mind which made Net-SNMP and others not quite as pleasant to work with as I had hoped for (I generally dislike code generators), but you'll find the general structuring is very similar to that of Net-SNMP.  If you're looking for a full-featured RFC compliant SNMP implementation, Net-SNMP still seems to be your only free choice at the moment.  If you're looking for an embedded SNMP agent, Treck's SNMP agent is pretty neat (though not free).  This implementation is somewhat in between.

Other projects worth checking out:
- [Net-SNMP](http://www.net-snmp.org/): the go-to SNMP agent implementation, supports multiple operating systems, feature rich, but also quite heavy.
- [OpenSNMPd](http://opensnmp.sourceforge.net/sourceforge.net/projects/opensnmp/): object-oriented SNMP implementation from the same people that brought you Net-SNMP, though the project seems to be dead.
- [SNMP4J/AGENT++](http://www.agentpp.com/): Commerical SNMP agents for Java and C++ with free Apache-licensed subset.
- [bsnmpd](https://wiki.freebsd.org/Bsnmp): lightweight SNMPv3 capable agent for FreeBSD.
- [Treck Inc.'s SNMP agent](http://www.treck.com/treck-snmp-datasheet): commercial embedded SNMP agent
- [lwIP's SNMP agent](http://savannah.nongnu.org/projects/lwip/): free embedded SNMP agent
- [mini-snmpd](http://troglobit.github.io/mini-snmpd.html): tiny SNMPv1/v2c implementation for Linux

#### Why can't you be portable like Net-SNMP?

Net-SNMP isn't truly portable either; they support antiquarian systems like DYNIX/ptx, but don't bother to support QNX properly (which as we all know is the only true POSIX operating system :-).  Since I intended to run this on an embedded device, I only needed Linux support.  Adding support for systems I don't have access to would probably only result in even more bugs and security issues than I already unwillingly introduced.

#### Can you at least guarantee this implementation is conform with the SNMPv2/3 RFCs?

I travel the path of least resistence: I break no SNMP clients, nor do I comply with their standards (that's a fancy way of saying I didn't bother to be RFC compliant :-).  Restrictive/permissive access rights on attributes, missing attributes, missing MIBs which are mandatory, missing security settings, this agent has it all.  My main concern was being able to transfer statistics in a secure way to existing clients.  I've validated compatibility with the following applications:

- [Net-SNMP](http://www.net-snmp.org/): both walking the tree and receiving events works fine, though legacy security should be enabled.
- [OidView Network Management Tools](http://www.oidview.com/products.html): walking the tree works, but again only with legacy security enabled.
- [iReasoning MIB browser](http://www.ireasoning.com/mibbrowser.shtml): quite a few stacktraces in their logging, but this client supports all USM security profiles.
- [ZoHo MIBBrowser](https://www.manageengine.com/products/mibbrowser-free-tool/): this application stacktraces when I try to send it an inform notification;  I haven't been able to get that working, but I notice they've replaced their old Java application on their website with a newer client that unfortunately doesn't work under wine, so I can't test that.

Should there be issues with other clients, let me know and I'll fix it right away.

#### Doesn't that make this project useless for anything serious?

Probably.

#### This isn't a real FAQ! This whole project stinks!

That's not a question.

## Licensing

This software is licensed under the MIT License.

