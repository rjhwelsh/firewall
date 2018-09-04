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

    @classmethod
    def iter(cls):
        """ Iterates over all network interfaces. """
        def __get_all_ifs():
            for n in netifaces.interfaces():
                yield cls(name=n)
        return __get_all_ifs()

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
             restrict_in=True,
             restrict_out=True):
        """ Generates a RuleArray based on network interface.
        table -- the name of the table
        chain -- the name of the chain
        src -- 0 = disable, 1 = gateway only, 2 = subnet, 3 = self
        dst -- (same as above)
        restrict_in -- True means restricts to in_interface if possible.
        restrict_out -- (as above) for out_interface
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
        if chain:
            for netif in self.__CHAIN_IF[chain]:
                if ((restrict_in and netif == "in_interface") or
                        (restrict_out and netif == "out_interface")):
                    params[netif] = name

        if not route[src]:
            rarr.append(
                Rule(params=params,
                     chain=chain,
                     table=table,
                     ipv=ipv))

        # Restrict rule to src/dst addresses
        for s, d in zip(route[src], route[dst]):
            if s:
                params['src'] = s
            if d:
                params['dst'] = d

            rarr.append(
                Rule(params=params,
                     chain=chain,
                     table=table,
                     ipv=ipv))

        return rarr
