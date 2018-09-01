#!/usr/bin/env python3


import unittest
import baleful.topo as T
import baleful.rule as R


class Test_Topo(unittest.TestCase):
    """ Tests for the Topo(logy) base class. """

    def testMul(self):
        """ Test __mul__ with Rules"""

        rule = R.RuleArray(R.Rule(chain="OUTPUT"))
        rule_reverse = R.RuleArray(R.Rule(chain="INPUT"))

        topo = T.Topology(rule, rule_reverse)

        route = R.Rule(params={'src': '192.168.1.10',
                               'dst': '192.168.1.1'})

        app = R.Rule(tcp={'dport': 22})

        combo = route + app
        reverse = combo.copy()
        reverse.reverse()

        rarr = topo * (route + app)

        self.assertEqual(rarr[0].dict(), combo.dict())
        self.assertEqual(rarr[1].dict(), reverse.dict())
