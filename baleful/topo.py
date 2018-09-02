#!/usr/bin/env python3

import baleful.rule

RuleArray = baleful.rule.RuleArray
Rule = baleful.rule.Rule


class Topology:
    """Provides a base class for iptables rule generation based on network
    topology.
    """

    def __init__(self, ruleArray: RuleArray,
                 ruleArray_flip: RuleArray):
        """ Constructs a Topology instance.
        This consists of two rules:
        ruleArray -- a ruleArray to apply to normal rules
        ruleArray_flip -- a ruleArray to apply to flip rules
        """
        self.ruleArray = ruleArray
        self.ruleArray_flip = ruleArray_flip

    def __mul__(self, other: Rule):
        """ Multiplies Topology objects with a Rule"""
        newArray = baleful.rule.RuleArray()
        j = other.copy()

        ruleArray = self.ruleArray
        ruleArray_flip = self.ruleArray_flip

        newArray += ruleArray * other
        j.flip()
        newArray += ruleArray_flip * j

        return newArray

    def __rmul__(self, other: Rule):
        """ Multiplies Topology with a Rule (Right) """
        newArray = baleful.rule.RuleArray()
        j = other.copy()

        ruleArray = self.ruleArray
        ruleArray_flip = self.ruleArray_flip

        newArray += other * ruleArray
        j.flip()
        newArray += j * ruleArray_flip

        return newArray

    def __matmul__(self, other: RuleArray):
        """ Multiplies Topology objects with a RuleArray """
        newArray = baleful.rule.RuleArray()

        for i in other:
            newArray += self * i

        return newArray
