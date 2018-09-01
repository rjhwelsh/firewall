#!/usr/bin/env python3

import baleful.rule

RuleArray = baleful.rule.RuleArray
Rule = baleful.rule.Rule

"""Applications which are instances of the RuleArray class are instantiated and
defined here.
Applications are defined with respect to a client node, see the Topology class
for dealing with different NetworkTopology models. See Rule class for the
'reverse' method which instantiates the alternative rule for Servers. """


ssh = RuleArray(
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 22}))

dns = RuleArray(
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 53}),
    Rule(
        params={'protocol': 'udp'},
        udp={'dport': 53}))

dhcp = RuleArray(
    Rule(
        params={'protocol': 'udp'},
        udp={'dport': 67,
             'sport': 68}))

http = RuleArray(
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 80}))

rpcbind = RuleArray(
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 111}),
    Rule(
        params={'protocol': 'udp'},
        udp={'dport': 111}))

ntp = RuleArray(
    Rule(
        params={'protocol': 'udp'},
        udp={'dport': 123}))

snmp = RuleArray(
    Rule(
        params={'protocol': 'udp'},
        udp={'dport': 161}))

https = RuleArray(
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 443}))

smtp = RuleArray(
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 587}))

cups = RuleArray(
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 631}),
    Rule(
        params={'protocol': 'tcp'},
        tcp={'sport': 631}))

rsync = RuleArray(
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 873}))

imaps = RuleArray(
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 993}))

nfs = rpcbind + RuleArray(
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 2049}),
    Rule(
        params={'protocol': 'udp'},
        udp={'dport': 2049}),
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': "51378:51379"}),
    Rule(
        params={'protocol': 'udp'},
        udp={'dport': "51378:51379"}),
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 55461}),
    Rule(
        params={'protocol': 'udp'},
        udp={'dport': 55461}))

sip = RuleArray(
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 5060}),
    Rule(
        params={'protocol': 'udp'},
        udp={'dport': 5060}),
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 3478}),
    Rule(
        params={'protocol': 'udp'},
        udp={'dport': 3478}),
    Rule(
        params={'protocol': 'udp'},
        udp={'dport': "7076:7079"}),
    Rule(
        params={'protocol': 'udp'},
        udp={'dport': "9076:9079"}))

skype = https + RuleArray(
    Rule(
        params={'protocol': 'udp'},
        tcp={'dport': "3478:3481"}),
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': "49152:65535"}),
    Rule(
        params={'protocol': 'udp'},
        udp={'dport': "49152:65535"}))

google_hangouts = RuleArray(
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 5222}))

avahi = RuleArray(
    Rule(
        params={'protocol': 'udp'},
        udp={'dport': 5353}))

irc = RuleArray(
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 6667}),
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 6697}),
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 7000}))

pgp = RuleArray(
    Rule(
        params={'protocol': 'tcp'},
        tcp={'dport': 11371}))

openvpn = RuleArray(
    Rule(
        params={'protocol': 'udp'},
        udp={'dport': 26009}))

