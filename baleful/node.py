#!/usr/bin/env python3

import iptc
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
        """ Sets the policy for node. """

    def start(self):
        """ Starts iptables instance for node. """

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
