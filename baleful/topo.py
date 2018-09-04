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
        yreverse_flipped = y.forward.copy()

        for i, j in zip(yforward_flipped,
                        yreverse_flipped):
            i.flip()
            j.flip()

        return Topology(
            forward=xforward * (yforward + yreverse),
            reverse=xreverse * (yforward_flipped + yreverse_flipped))

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

        if key < len(self.forward) and key >= 0:
            return self.forward[key]

        if key < 0 - len(self.reverse):
            key += len(self.reverse)
            return self.forward[key]

        if key < len(self.forward) + len(self.reverse):
            key -= len(self.forward)
            return self.reverse[key]

        if key < 0:
            return self.reverse[key]

        raise IndexError
