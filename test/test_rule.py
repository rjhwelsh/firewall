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
                                 target="ACCEPT",
                                 params={'protocol': 'tcp',
                                         'src': '127.0.0.1'},
                                 tcp={'dport': 22})

        rule = rule_ssh_client.create()

        self.assertEqual(rule.protocol, 'tcp')
        self.assertEqual(rule.src, '127.0.0.1/255.255.255.255')

        # Test matches in rule.
        self.assertEqual(rule._matches[0].dport, '22')

    def testRuleReverse(self):
        """ Test rule reversal. """
        rule_ssh_client = R.Rule(ipv=4,
                                 chain='OUTPUT',
                                 target="ACCEPT",
                                 params={'protocol': 'tcp',
                                         'dst': '127.1.1.0',
                                         'src': '127.0.0.1'},
                                 tcp={'dport': 22},
                                 icmp={'icmp_type': 'echo-request'})

        rule_ssh_client.reverse()

        rule = rule_ssh_client.create()

        self.assertEqual(rule.protocol, 'tcp')
        self.assertEqual(rule.dst, '127.0.0.1/255.255.255.255')

        # Test matches in rule.
        self.assertEqual(rule_ssh_client.kwargs['tcp']['sport'], 22)

        # Test chain reversal
        self.assertEqual(rule_ssh_client.chain, 'INPUT')

        # Test icmp reversal
        self.assertEqual(
            rule_ssh_client.kwargs['icmp']['icmp_type'], 'echo-reply')

    def testRuleAddition(self):
        """ Test rule addition. """

        rule_ssh_client_1 = R.Rule(ipv=4,
                                   chain='OUTPUT',
                                   target="ACCEPT",
                                   params={'protocol': 'tcp',
                                           'dst': '127.1.1.0',
                                           'src': '127.0.0.1'},
                                   tcp={'dport': 22})

        rule_ssh_client_2 = R.Rule(tcp={'sport': 23},
                                   icmp={'icmp_type': 'echo-request'})

        rule_ssh_client = rule_ssh_client_1 + rule_ssh_client_2

        # Test matches in rule.
        self.assertEqual(rule_ssh_client.kwargs['tcp']['dport'], 22)
        self.assertEqual(rule_ssh_client.kwargs['tcp']['sport'], 23)

        # Test chain reversal
        self.assertEqual(rule_ssh_client.chain, 'OUTPUT')

        # Test icmp reversal
        self.assertEqual(
            rule_ssh_client.kwargs['icmp']['icmp_type'], 'echo-request')

    def testRuleAdditionOverrides(self):
        """ Test rule addition precedence. """

        ssh_client = R.Rule(tcp={'dport': 22})
        http_client = R.Rule(tcp={'dport': 80})

        ssh = http_client + ssh_client
        http = ssh_client + http_client

        self.assertEqual(ssh.kwargs['tcp']['dport'], 22)
        self.assertEqual(http.kwargs['tcp']['dport'], 80)

    def testRuleSubtraction(self):
        """ Test rule subtraction. """
        rule_ssh_client_1 = R.Rule(ipv=4,
                                   chain='OUTPUT',
                                   target="ACCEPT",
                                   params={'protocol': 'tcp',
                                           'dst': '127.1.1.0',
                                           'src': '127.0.0.1'},
                                   tcp={'dport': 22,
                                        'sport': 23})

        rule_ssh_client_2 = R.Rule(tcp={'dport': 22,
                                        'sport': 24},
                                   icmp={'icmp_type': 'echo-request'})

        rule_ssh_client = rule_ssh_client_1 - rule_ssh_client_2

        self.assertNotIn('dport', rule_ssh_client.kwargs['tcp'])
        self.assertIn('sport', rule_ssh_client.kwargs['tcp'])


class Test_RuleArray(unittest.TestCase):
    """ Tests for the Rule Array. """

    def testRuleArrayInit(self):
        """ Test Rule Array Initialization. """

        ssh_client = R.Rule(tcp={'dport': 22})
        http_client = R.Rule(tcp={'dport': 80})

        rarr = R.RuleArray(ssh_client, http_client)

        self.assertEqual(rarr[0], ssh_client)
        self.assertEqual(rarr[1], http_client)

        with self.assertRaises(TypeError):
            rarr2 = R.RuleArray(1, 2)
