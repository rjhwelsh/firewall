#!/usr/bin/env python3

import ipaddress
import baleful.rule


class Address:
    """ Provides a base class for handling addresses. """

    def __init__(self, addr):
        """ Arguments:
        addr -- The address string
        """
        if addr:
            self.addr = ipaddress.ip_address(addr)
        else:
            self.addr = str()

    def __str__(self):
        return str(self.addr)

    def __bool__(self):
        return bool(self.addr)


class Route(baleful.rule.Rule):
    """ Provides a base class for handling routes.
    Routes are a (Source, Destination) address tuple.

    Routes are always described from the perspective of a Client.
    Hence,
    Source -- Client Address
    Destination -- Server Address

    See Topo for how routes are handled to produce an iptables rule.
    """

    def __init__(self, src, dst, params=None, **kwargs):
        """Arguments:
        src -- The source "client" Address
        dst -- The destination "server" Address
        params -- Additional rule parameters
        kwargs -- Additional match parameters
        """

        # Check src and dst address types match
        if src and dst:
            if not isinstance(dst.addr, type(src.addr)):
                raise(
                    ValueError(
                        "{} is not an instance of {}".format(
                            dst.addr, type(src.addr))))

        # Initialize params if empty
        if isinstance(params, type(None)):
            params = dict()

        # Check src and dst are not in params
        if 'src' in params or 'dst' in params:
            raise(
                ValueError(
                    'src/dst should not be specified in params!'))

        self.src = src
        self.dst = dst

        if src:
            params.update({'src': src})

        if dst:
            params.update({'dst': dst})

        super().__init__(params, **kwargs)

    def __str__(self):
        return '{} -> {}'.format(self.src, self.dst)
