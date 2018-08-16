#!/usr/bin/env python3

import netifaces


class NetworkInterface:
    protocols = {
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

        for p, n in self.protocols.items():
            self.addr[p] = addrs[n] if n in addrs else list()
            self.gate[p] = gws[n] if n in gws else list()
