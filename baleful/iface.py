#!/usr/bin/env python3

import netifaces
from baleful.rule import Rule, RuleArray


class NetworkInterface:
    PROTOCOLS = {
        "ip": netifaces.AF_INET,
        "ip6": netifaces.AF_INET6,
        "link": netifaces.AF_LINK
    }

    def __init__(self, name=str()):
        """Keyword Arguments:
        name -- the name of the interface
        """

        interfaces = netifaces.interfaces()
        if name in interfaces:
            self.name = name
        else:
            raise ValueError("No such interface!")

        # Refresh interface data
        self.gate = dict()
        self.addr = dict()
        self.refresh()

    def refresh(self):
        """ Refresh protocol gateways and addresses."""
        addrs = netifaces.ifaddresses(self.name)
        gws = netifaces.gateways()

        for p, n in self.PROTOCOLS.items():
            self.addr[p] = addrs[n] if n in addrs else list()
            self.gate[p] = [gate
                            for gate in gws[n]
                            if gate[1] == self.name] if n in gws else list()

    __CHAIN_IF = {"PREROUTING": ['in_interface'],
                  "INPUT": ['in_interface'],
                  "FORWARD": ['in_interface', 'out_interface'],
                  "OUTPUT": ['out_interface'],
                  "POSTROUTING": ['out_interface']}

    def rule(self,
             table=None,
             chain=None,
             ipv=4,
             src=0,
             dst=0,
             restrict=True):
        """ Generates a RuleArray based on network interface.
        table -- the name of the table
        chain -- the name of the chain
        src -- 0 = disable, 1 = gateway only, 2 = subnet, 3 = self
        dst -- (same as above)
        restrict -- True means restricts to interface if possible.
        ( Worked out based on table/chain) """

        p = "ip"
        if ipv == 6:
            p = "ip6"

        name = self.name
        addr = self.addr[p]
        gate = self.gate[p]

        rarr = RuleArray()

        route = {0: [None for g in gate],
                 1: [g[0] for g in gate],
                 2: ['/'.join([a['addr'], a['netmask']])
                     for a in addr],
                 3: [a['addr'] for a in addr]}

        params = dict()
        # Restrict rule to network interface
        if restrict and chain:
            for netif in self.__CHAIN_IF[chain]:
                params[netif] = name

        # Restrict rule to src/dst addresses
        for s, d in zip(route[src], route[dst]):
            params['src'] = s
            params['dst'] = d
            rarr.append(
                Rule(params=params,
                     chain=chain,
                     table=table,
                     ipv=ipv))

        return rarr
