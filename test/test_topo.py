#!/usr/bin/env python3


import unittest
import baleful.topo as T
import baleful.rule as R


class Test_Topo(unittest.TestCase):
    """ Tests for the Topo(logy) base class. """

    def testMul(self):
        """ Test __mul__ with Rules"""

        rule = R.RuleArray(R.Rule(chain="OUTPUT"))
        rule_flip = R.RuleArray(R.Rule(chain="INPUT"))

        topo = T.Topology(rule, rule_flip)

        route = R.Rule(params={'src': '192.168.1.10',
                               'dst': '192.168.1.1'})

        app = R.Rule(tcp={'dport': 22})

        combo = route + app
        flip = combo.copy()
        flip.flip()

        rarr = topo * (route + app)

        self.assertEqual(rarr[0].dict(), combo.dict())
        self.assertEqual(rarr[1].dict(), flip.dict())

    def testRmul(self):
        """ Test __rmul__ with Rules """

        rule = R.RuleArray(R.Rule(chain="OUTPUT"))
        rule_flip = R.RuleArray(R.Rule(chain="INPUT"))

        topo = T.Topology(rule, rule_flip)

        route = R.Rule(params={'src': '192.168.1.10',
                               'dst': '192.168.1.1'})

        app = R.Rule(tcp={'dport': 22})

        combo = route + app
        flip = combo.copy()
        flip.flip()

        rarr = (route + app) * topo

        self.assertEqual(rarr[0].dict(), combo.dict())
        self.assertEqual(rarr[1].dict(), flip.dict())

    def testMatmul(self):
        """ Test __matmul__ with RuleArray """

        rule = R.RuleArray(R.Rule(chain="OUTPUT"))
        rule_flip = R.RuleArray(R.Rule(chain="INPUT"))

        topo = T.Topology(rule, rule_flip)

        route = R.Rule(params={'src': '192.168.1.10',
                               'dst': '192.168.1.1'})

        app = R.Rule(tcp={'dport': 22})
        app2 = R.Rule(tcp={'dport': 80})

        appArray = R.RuleArray(app, app2)

        combo = route * appArray
        flip = combo.copy()
        for r in flip:
            r.flip()

        rarr = topo @ (route * appArray)

        for c, r in enumerate(combo):
            self.assertEqual(rarr[2*c+0].dict(), combo[c].dict())
            self.assertEqual(rarr[2*c+1].dict(), flip[c].dict())

        with self.assertRaises(TypeError):
            (route * appArray) @ topo
