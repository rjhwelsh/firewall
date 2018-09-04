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

    def __mul__(self, other: Rule):
        """ Multiplies Topology objects with a Rule"""
        newArray = baleful.rule.RuleArray()
        j = other.copy()

        forward = self.forward
        reverse = self.reverse

        newArray += forward * other
        j.flip()
        newArray += reverse * j

        return newArray

    def __rmul__(self, other: Rule):
        """ Multiplies Topology with a Rule (Right) """
        newArray = baleful.rule.RuleArray()
        j = other.copy()

        forward = self.forward
        reverse = self.reverse

        newArray += other * forward
        j.flip()
        newArray += j * reverse

        return newArray

    def __matmul__(self, other: RuleArray):
        """ Multiplies Topology objects with a RuleArray
        N.B. Topology rules take precedence over RuleArray rules.
        Topology @ RuleArray -> RuleArray(new) ONLY"""
        newArray = baleful.rule.RuleArray()

        for i in other:
            newArray += i * self

        return newArray
