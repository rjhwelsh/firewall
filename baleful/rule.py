#!/usr/bin/env python3

import iptc


class Rule:
    """ A rule generator base class for iptc/ip6tc. """

    IPTABLES = {4: {'module': iptc,
                    'rule': iptc.Rule,
                    'table': iptc.Table},
                6: {'module': iptc,
                    'rule': iptc.Rule6,
                    'table': iptc.Table6}}

    def __init__(self,
                 params=dict(),
                 target=None,
                 chain=None,
                 table="FILTER",
                 ipv=4,
                 **kwargs):
        """Keyword Arguments:
        params -- iptc rule parameters (dict)
        target -- the target of the rule (str)
        chain -- the chain to put the rule in (str)
        table -- the table to put the rule in (str)
        ipv -- The inet version 4 or 6 (int)
        **kwargs    -- iptc match module parameters (dict)

        Example:
        params := { 'protocol': "tcp", src: "::1" }
        tcp = { dport:80, sport: ... }
        mark = { ... }
        """

        self.ipv = ipv
        self.target = target
        self.chain = chain
        self.table = table
        self.params = params
        self.kwargs = kwargs

    def dict(self):
        """ Return a dictionary view of rule arguments. """
        kwargs = self.kwargs.copy()
        kwargs.update(
            {'': self.params.copy()})
        return kwargs

    def create(self):
        """ Returns an iptc rule """
        rule = self.IPTABLES[self.ipv]['rule']()

        # Setup method table
        set_methods = {'src': rule.set_src,
                       'dst': rule.set_dst,
                       'in_interface': rule.set_in_interface,
                       'out_interface': rule.set_out_interface,
                       'fragment': rule.set_fragment,
                       'protocol': rule.set_protocol}

        # Set target
        rule.create_target(self.target)

        # Set rule params
        for arg, val in self.params.items():
            set_methods[arg](
                str(val))

        # Set match params
        for m, params in self.kwargs.items():
            match = rule.create_match(m)
            for arg, val in params.items():
                match.__dict__[arg] = str(val)

        return rule
