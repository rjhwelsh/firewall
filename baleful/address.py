#!/usr/bin/env python3

import ipaddress


class Address:
    """ Provides a base class for handling addresses. """
    def __init__(self, addr):
        """ Arguments:
        addr -- The address string
        """
        self.addr = ipaddress.ip_address(addr)

    def __str__(self):
        return str(self.addr)


class Route:
    """ Provides a base class for handling routes.
    Routes are a (Source, Destination) address tuple.

    Routes are always described from the perspective of a Client.
    Hence,
    Source -- Client Address
    Destination -- Server Address

    See Topo for how routes are handled to produce an iptables rule.
    """
    def __init__(self, src, dst, **kwargs):
        """Arguments:
        src -- The source "client" Address
        dst -- The destination "server" Address
        kwargs -- Additional rules for route.
        """

        # Check src and dst address types match
        if not isinstance(dst.addr, type(src.addr)):
            raise(
                ValueError(
                    "{} is not an instance of {}".format(
                        dst.addr, type(src.addr))))

        self.src = src
        self.dst = dst
        self.kwargs = kwargs

    def __str__(self):
        return '{} -> {}'.format(self.src, self.dst)
