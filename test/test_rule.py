#!/usr/bin/env python3

import unittest
import baleful.rule as R
import iptc


class Test_Rule(unittest.TestCase):
    """ Tests for the Rule Generator. """

    def testInit(self):
        """ Test rule initialization. """
        rinit = R.Rule()

        self.assertEqual(rinit.IPTABLES[4]['rule'], iptc.Rule)
        self.assertEqual(rinit.IPTABLES[4]['table'], iptc.Table)
        self.assertEqual(rinit.IPTABLES[6]['rule'], iptc.Rule6)
        self.assertEqual(rinit.IPTABLES[6]['table'], iptc.Table6)

    def testRuleCreation(self):
        """ Test rule creation. """
        rule_ssh_client = R.Rule(ipv=4,
                                 params={'protocol': 'tcp',
                                         'src': '127.0.0.1'},
                                 tcp={'dport': 22})

        rule = rule_ssh_client.create()

        self.assertEqual(rule.protocol, 'tcp')
        self.assertEqual(rule.src, '127.0.0.1/255.255.255.255')

        # Test matches in rule.
        self.assertEqual(rule._matches[0].dport, '22')
