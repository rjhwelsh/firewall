#!/usr/bin/env python3

from baleful.rule import Rule


class Node:
    """ Iptables firewall implementation for a node. """

    def __init__(self,
                 hostname=str(),
                 rules=None,
                 targets=None,
                 policy=None,
                 final_rules=None):
        """ Keyword arguments:
        hostname -- the hostname of the node (default "")
        rules -- a list of baleful rules
        polcy -- a dict of policies for the filter table
        """
        self.hostname = hostname
        self.rules = rules if rules else list()
        self.policy = policy if policy else {
            4: {"INPUT": "ACCEPT",
                "OUTPUT": "ACCEPT",
                "FORWARD": "ACCEPT"},
            6: {"INPUT": "ACCEPT",
                "OUTPUT": "ACCEPT",
                "FORWARD": "ACCEPT"}}
        self.final_rules = final_rules if final_rules else list()

    def set_policy(self):
        """ Sets the policy for node.
        Only policies described in self.policy will be set"""
        for i, v in self.policy.items():
            tableClass = Rule.IPTABLES[i]['table']
            for t in tableClass.ALL:
                table = tableClass(t)
                for chain in table.chains:
                    if chain.name in v:
                        chain.set_policy(v[chain.name])

    def start(self, position=None):
        """ Starts iptables instance for node.
        insert -- The position to insert rules at,
        otherwise rules will be appended"""

        # Reverse rule order if inserting
        rules = self.rules.copy() + self.final_rules.copy()
        if not isinstance(position, type(None)):
            rules.reverse()

        for rule in rules:
            iptc_rule = rule.iptc()
            if isinstance(position, type(None)):
                iptc_rule.chain.append_rule(
                    iptc_rule)
            else:
                iptc_rule.chain.insert_rule(
                    iptc_rule)

    def stop(self):
        """ Stops iptables instance for node. """

    def __str__(self):
        """ Returns a string of iptables actions to be performed. """

    def log(self):
        """ Changes the target of all rules to LOG. """

    def status(self):
        """ Returns the status of each rule. """

    def lock(self):
        """ Stops regular rules and implements lock down. """

    def panic(self):
        """ Panic, DROP all packets. """

    def flush(self):
        """ Clear all iptables rules. """

# TODO:
# TODO: Method for adding and subtracting nodes
# TODO: Add interfaces variable and methods
# TODO: Add known address variable and methods
