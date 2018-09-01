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

