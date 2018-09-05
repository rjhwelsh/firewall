#!/usr/bin/env python3

from baleful.rule import Rule
import iptc


class Node:
    """ Iptables firewall implementation for a node. """

    __PANIC__ = {
        4: {"INPUT": "DROP",
            "OUTPUT": "DROP",
            "FORWARD": "DROP"},
        6: {"INPUT": "DROP",
            "OUTPUT": "DROP",
            "FORWARD": "DROP"}}

    def __init__(self,
                 hostname=str(),
                 rules=None,
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
            for table in self.tables(ipv=[i]):
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
        """ Stops iptables instance for node.
        Deletes rules from iptables instance"""

        for rule in self.rules + self.final_rules:
            iptc_rule = rule.iptc()
            iptc_rule.chain.delete_rule(
                iptc_rule)

    def __str__(self):
        """ Returns a string of iptables actions to be performed. """
        string = ''
        for rule in self.rules + self.final_rules:
            string += str(rule)
            string += '\n'
        return string

    def status(self):
        """ Returns the status of each rule.
        Returns a tuple (exists, (packets, bytes)) """

        stats = list()
        for rule in self.rules + self.final_rules:
            stats.append(
                (rule.exists(), rule.iptc().get_counters()))

        return stats

    def lock(self):
        """ Stops regular rules and implements lock down. """

        self.panic()

        for rule in self.rules:
            if rule.lock:
                iptc_rule = rule.iptc()
                iptc_rule.chain.append_rule(
                    iptc_rule)

        for rule in self.final_rules:
            iptc_rule = rule.iptc()
            iptc_rule.chain.append_rule(
                iptc_rule)

    def panic(self):
        """ Panic, DROP all packets. """

        # Note (only the FILTER table needs to drop packets)
        # ALL CONNECTIONS PASS THRU FILTER

        # Set policy to DROP
        for i, v in self.__PANIC__.items():
            tableClass = Rule.IPTABLES[i]['table']
            table = tableClass(tableClass.FILTER)
            for chain in table.chains:
                chain.flush()

                # Delete chain if possible
                try:
                    chain.delete()
                except iptc.ip4tc.IPTCError:
                    pass
                except iptc.ip6tc.IPTCError:
                    pass

                if chain.name in v:
                    chain.set_policy(v[chain.name])

    def flush(self, ipv=[4, 6]):
        """ Clear all iptables rules.
        From all tables."""
        for i in ipv:
            tableClass = Rule.IPTABLES[i]['table']
            for t in tableClass.ALL:
                table = tableClass(t)
                for chain in table.chains:
                    chain.flush()

    def tables(self, ipv=[4, 6]):
        """ Refreshs all the tables. """
        for i in ipv:
            tableClass = Rule.IPTABLES[i]['table']
            for t in tableClass.ALL:
                table = tableClass(t)
                yield table
