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

        combo = route * app * rule[0]
        flip = combo.copy()
        flip.flip()

        rarr = topo * (route * app)

        self.assertEqual(rarr[0].dict(), combo.dict())
        self.assertEqual(rarr[1].dict(), flip.dict())
        self.assertEqual(len(rarr), 2)

    def testRmul(self):
        """ Test __rmul__ with Rules """
    def testMulTopology(self):
        rule = R.RuleArray(R.Rule(chain="OUTPUT"))
        rule_flip = R.RuleArray(R.Rule(chain="INPUT"))
        topo1 = T.Topology(rule, rule_flip)

        topo2 = T.Topology(
            R.RuleArray(
                R.Rule(
                    params={'protocol': 'tcp'},
                    tcp={'dport': 54921})),
            # Scanner (server) connection to client
            R.RuleArray(
                R.Rule(
                    params={'protocol': 'udp'},
                    udp={'dport': 54925})))

        topo3 = (topo1 * topo2)

        self.assertEqual(topo3[0].dict()['chain'], "OUTPUT")
        self.assertEqual(topo3[0].dict()['tcp']['dport'], 54921)
        self.assertEqual(topo3[1].dict()['chain'], "OUTPUT")
        self.assertEqual(topo3[1].dict()['udp']['sport'], 54925)
        self.assertEqual(topo3[2].dict()['chain'], "INPUT")
        self.assertEqual(topo3[2].dict()['tcp']['sport'], 54921)
        self.assertEqual(topo3[3].dict()['chain'], "INPUT")
        self.assertEqual(topo3[3].dict()['udp']['dport'], 54925)

        # for r in topo3:
        #     print('{}, {}, src: {}, dst: {}'.format(
        #         r.dict()['chain'],
        #         r.dict()['tcp'] if 'tcp' in r.dict() else r.dict()['udp'],
        #         r.dict()['']['src'],
        #         r.dict()['']['dst'],
        #     ))


        rule = R.RuleArray(R.Rule(chain="OUTPUT"))
        rule_flip = R.RuleArray(R.Rule(chain="INPUT"))

        topo = T.Topology(rule, rule_flip)

        route = R.Rule(params={'src': '192.168.1.10',
                               'dst': '192.168.1.1'})

        app = R.Rule(tcp={'dport': 22})

        combo = route * app * rule[0]

        flip = combo.copy()
        flip.flip()

        rarr = (route * app) * topo

        self.assertEqual(rarr[0].dict(), combo.dict())
        self.assertEqual(rarr[1].dict(), flip.dict())

    def testGetItem(self):
        """ Test __getitem__ with Rules. """

        rule = R.RuleArray(R.Rule(chain="OUTPUT"))
        rule_flip = R.RuleArray(R.Rule(chain="INPUT"))

        topo = T.Topology(rule, rule_flip)

        self.assertEqual(topo[0], rule[0])
        self.assertEqual(topo[1], rule_flip[0])

        with self.assertRaises(IndexError):
            topo[2]

        with self.assertRaises(TypeError):
            topo['string']
