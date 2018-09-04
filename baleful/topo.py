#!/usr/bin/env python3

import baleful.rule

RuleArray = baleful.rule.RuleArray
Rule = baleful.rule.Rule


class Topology:
    """Provides a base class for iptables rule generation based on network
    topology.
    """

    def __init__(self, forward: RuleArray,
                 reverse=None):
        """ Constructs a Topology instance.
        This consists of two rules:
        forward -- a RuleArray to apply to normal rules
        reverse -- a RuleArray to apply to flip rules
        """
        self.forward = forward
        self.reverse = reverse if reverse else RuleArray()

    @staticmethod
    def combine(x, y):
        """ Combines two topologies together.
         x.f*(y.f + y.r) x.r*(y.fr + y.rr)"""

        xforward = x.forward
        xreverse = x.reverse

        yforward = y.forward
        yreverse = y.reverse

        yforward_flipped = y.forward.copy()
        yreverse_flipped = y.reverse.copy()

        for i in yforward_flipped + yreverse_flipped:
            i.flip()

        return Topology(
            forward=xforward * yforward + xforward * yreverse_flipped,
            reverse=xreverse * yforward_flipped + xreverse * yreverse)

    def __mul__(self, other):
        if isinstance(other, Rule):
            y = Topology(RuleArray(other))
        elif isinstance(other, RuleArray):
            y = Topology(other)
        elif isinstance(other, Topology):
            y = other
        else:
            return NotImplemented

        return self.combine(self, y)

    def __rmul__(self, other):
        if isinstance(other, Rule):
            y = Topology(RuleArray(other))
        elif isinstance(other, RuleArray):
            y = Topology(other)
        elif isinstance(other, Topology):
            y = other
        else:
            return NotImplemented

        return self.combine(self, y)

    def __iter__(self):
        def generator(self):
            for rule in self.forward:
                yield rule

            for rule in self.reverse:
                yield rule

        return generator(self)

    def __getitem__(self, key: int):
        """ Returns rule item from Topology,
        ordered thru self.forward, then self.reverse. """
        return (self.forward + self.reverse)[key]

    def __len__(self):
        """ Returns the length of the Topology. """
        return len(self.forward) + len(self.reverse)
