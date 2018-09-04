#!/usr/bin/env python3

import baleful.rule

RuleArray = baleful.rule.RuleArray
Rule = baleful.rule.Rule


class Topology:
    """Provides a base class for iptables rule generation based on network
    topology.
    """

    def __init__(self, forward: RuleArray,
                 reverse: RuleArray):
        """ Constructs a Topology instance.
        This consists of two rules:
        forward -- a RuleArray to apply to normal rules
        reverse -- a RuleArray to apply to flip rules
        """
        self.forward = forward
        self.reverse = reverse

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







