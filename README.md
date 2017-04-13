osnmpd Agent
============

## Overview

osnmpd is a lightweight SNMPv3 agent, with focus on low memory footprint and simplicity.  The MIB is loaded as a set of shared objects; the included modules provide statistics on memory, CPU and network usage, and a few more.  Trap and Inform notifications can be handed to the agent via a message queue.  A fixed set of security profiles are available, using the user-based security model (USM).

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

The SNMP agent stores its configuration in a file located at /etc/snmp/snmpd.conf

Configuration changes emitted via the control interface overwrite this file.

## Use

Start and use the SNMP agent like any normal daemon process

```sh
/etc/init.d/osnmpd {start,stop,restart}
```

## MIB modules

A few basic MIB modules are included in the package:

- BATTERY-MIB
- ENTITY-SENSORS-MIB
- HOST-RESOURCES-MIB
- IF-INVERTED-STACK-MIB
- IF-MIB
- IP-MIB
- NETWORK-SERVICES-MIB
- RFC1213-MIB
- SNMP-FRAMEWORK-MIB
- SNMP-MPD-MIB
- SNMP-NOTIFICATION-MIB
- SNMP-TARGET-MIB
- SNMP-USER-BASED-SM-MIB
- SNMPv2-MIB
- SNMP-VIEW-BASED-ACM-MIB
- TCP-MIB
- UCD-SNMP-MIB
- UDP-MIB

Only the relevant parts of these modules are implemented.

## FAQ

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

Net-SNMP isn't truly portable either; they support antiquarian systems like DYNIX/ptx, but don't bother to support QNX properly (which as we all know is the only true POSIX operating system :-).  Since I intended to run this on an embedded device, I only needed Linux support.  Adding support for systems I don't have access to would probably only result in even more bugs and security issues.

#### Can you at least guarantee this implementation is conform with the SNMPv2/3 RFCs?

You're funny.

#### Doesn't that make this project useless for anything serious?

Probably.

#### This isn't a real FAQ! This whole project stinks!

That's not a question.

## Licensing

This software is licensed under the MIT License.

