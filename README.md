osnmpd Agent
============

## Overview

osnmpd is a lightweight SNMPv3 agent, with focus on low memory footprint and simplicity.

This document gives an overview on how to compile, setup and use the agent.

## Installation

Installation uses the standard autotools commands:

- autoreconf -i
- ./configure
- make
- make install
- etc.

## Configuration

The SNMP agent stores its configuration in a file located at /etc/snmp/osnmpd.conf
Configuration changes emitted via the control interface overwrite this file.

## Use

Start the SNMP agent as any normal daemon process

/etc/init.d/osnmpd {start,stop,restart}

## MIB modules

Only the most basic MIB modules are included in the package.

## FAQ

#### Why not use net-snmp/bsnmpd/OpenSNMPd instead?

In pretty much all cases, that would be the sane choice.  I had some specific goals in mind (low footprint, Linux-friendly, easy to extend) which made net-snmp and others not quite as pleasant to work with as I hoped for, but I'd be hard-pressed to find anyone who has a valid excuse for choosing this instead of a well-tested, well-maintained, versatile piece of software like net-snmp.

#### Can you at least guarantee this implementation is conform with the SNMPv2/3 RFCs?

You're funny.

#### Doesn't that make this project useless for anything serious?

Probably.

#### This project sucks!

That's not a question.

## Licensing

This software is licensed under the MIT License.

