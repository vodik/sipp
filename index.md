---
layout: default
title: Welcome
---

# SIPp Docs

## Foreward

SIPp is a performance testing tool for the SIP protocol. It includes a few
basic SipStone user agent scenarios (UAC and UAS) and establishes and releases
multiple calls with the INVITE and BYE methods. It can also reads XML scenario
files describing any performance testing configuration. It features the dynamic
display of statistics about running tests (call rate, round trip delay, and
message statistics), periodic CSV statistics dumps, TCP and UDP over multiple
sockets or multiplexed with retransmission management, regular expressions and
variables in scenario files, and dynamically adjustable call rates.

SIPp can be used to test many real SIP equipments like SIP proxies, B2BUAs,
SIP media servers, SIP/x gateways, SIP PBX, ... It is also very useful to
emulate thousands of user agents calling your SIP system.

## Installation

### Getting SIPp

SIPp is released under the [GNU GPL
license](http://www.gnu.org/copyleft/gpl.html). All the terms of the license
apply. It was originally created and provided to the SIP community by
[Hewlett-Packard](http://www.hp.com) engineers in hope it can be useful, but
**HP does not provide any support nor warranty concerning SIPp**.

### Stable release

Like many other "open source" projects, there are two versions of SIPp:
a stable and unstable release. Stable release: before being labelled as
"stable", a SIPp release is thoroughly tested. So you can be confident that all
mentioned features will work :)

> Use the stable release for your everyday use and if you are not blocked by
a specific feature present in the "unstable release" (see below).
