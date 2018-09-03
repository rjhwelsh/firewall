#!/usr/bin/env python3

import unittest
import baleful.rule as R
import iptc
import ipaddress


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

        try:
            rule = rule_ssh_client.iptc()
        except iptc.ip4tc.IPTCError as e:
            raise unittest.SkipTest(e)

        self.assertEqual(rule.protocol, 'tcp')
        self.assertEqual(rule.src, '127.0.0.1/255.255.255.255')

        # Test matches in rule.
        self.assertEqual(rule._matches[0].dport, '22')

    def testRuleConversion(self):
        """ Test rule conversion from iptc.rule """
        rule = R.Rule(ipv=4,
                      target="ACCEPT",
                      params={'protocol': 'tcp',
                              'src': '127.0.0.1'},
                      tcp={'dport': 22})

        try:
            iptc_rule = rule.iptc()
        except iptc.ip4tc.IPTCError as e:
            raise unittest.SkipTest(e)

        conv_rule = R.Rule.from_iptc(iptc_rule)

        self.assertEqual(conv_rule, rule)
        self.assertEqual(conv_rule.target, "ACCEPT")
        self.assertEqual(conv_rule.chain, "OUTPUT")
        self.assertEqual(conv_rule.table, "FILTER")

    def testRuleExists(self):
        """ Test rule existence in iptables. """
        rule_not_exist = R.Rule(ipv=4,
                                target="ACCEPT",
                                params={'protocol': 'tcp',
                                        'src': '127.0.0.1'},
                                tcp={'dport': 22})

        rule_exists = R.Rule(ipv=4,
                             target="ACCEPT",
                             params={'protocol': 'tcp'},
                             tcp={'dport': 22})

        try:
            self.assertFalse(rule_not_exist.exists())
            self.assertTrue(rule_exists.exists())
        except iptc.ip4tc.IPTCError as e:
            raise unittest.SkipTest(e)

    def testRuleFlip(self):
        """ Test rule reversal. """
        rule = R.Rule(ipv=4,
                      chain='OUTPUT',
                      target="ACCEPT",
                      params={'protocol': 'tcp',
                              'dst': '127.1.1.0/255.255.255.255',
                              'src': '127.0.0.1/255.255.255.255'},
                      tcp={'dport': 22},
                      icmp={'icmp_type': 'echo-request'})

        rule_flipped = rule.copy()
        rule_flipped.flip()

        self.assertEqual(rule_flipped.params['protocol'], 'tcp')
        self.assertEqual(
            str(rule_flipped.params['dst']),
            '127.0.0.1/32')
        self.assertEqual(
            str(rule_flipped.params['src']),
            '127.1.1.0/32')

        # Test matches in rule.
        self.assertEqual(rule_flipped.kwargs['tcp']['sport'], 22)

        # Test chain reversal
        self.assertEqual(rule_flipped.chain, 'INPUT')

        # Test icmp reversal
        self.assertEqual(
            rule_flipped.kwargs['icmp']['icmp_type'], 'echo-reply')

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

        with self.assertRaises(TypeError):
            http_client + list()

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

        with self.assertRaises(TypeError):
            rule_ssh_client - list()

    def testEqualityOperator(self):
        """ Tests rule equality relation."""

        ssh_client = R.Rule(tcp={'dport': 22})
        ssh_client2 = R.Rule(tcp={'dport': 22})
        http_client = R.Rule(tcp={'dport': 80})

        self.assertEqual(ssh_client, ssh_client2)
        self.assertNotEqual(ssh_client, http_client)

        with self.assertRaises(TypeError):
            http_client == list()

    def testMembership(self):
        """ Tests membership methods. """

        specific_rule_match = R.Rule(ipv=4,
                                     target="ACCEPT",
                                     params={'protocol': 'tcp',
                                             'src': '127.0.0.1'},
                                     tcp={'dport': 22})

        specific_rule_nomatch = R.Rule(ipv=4,
                                       target="ACCEPT",
                                       params={'protocol': 'udp',
                                               'src': '127.0.0.1'},
                                       tcp={'dport': 22})

        general_rule = R.Rule(ipv=4,
                              target="ACCEPT",
                              params={'protocol': 'tcp'},
                              tcp={'dport': 22})

        self.assertIn(specific_rule_match, general_rule)
        self.assertNotIn(specific_rule_nomatch, general_rule)

        try:
            for rule in general_rule.matches():
                print(rule.dict())
        except iptc.ip4tc.IPTCError as e:
            raise unittest.SkipTest(e)


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
            R.RuleArray(1, 2)

    def testRuleMultiplication(self):
        """ Test Rule Array Multiplication. """

        ssh_client = R.Rule(tcp={'dport': 22})
        http_client = R.Rule(tcp={'dport': 80})
        rarr = R.RuleArray(ssh_client, http_client)

        lo_route = R.Rule(params={'src': '127.0.0.1',
                                  'dst': '127.0.0.1'})

        rarr_lo = rarr * lo_route

        for rule in rarr:
            for key in ['src', 'dst']:
                self.assertEqual(rule.params[key], ipaddress.ip_network(
                    "0.0.0.0/0"))

        for rule in rarr_lo:
            for key in ['src', 'dst']:
                self.assertEqual(rule.params[key],
                                 lo_route.params[key])

        with self.assertRaises(TypeError):
            rarr * list()

    def testRuleMultiplicationOverride(self):
        """ Tests Rule Multiplication RHS precedence. """

        ssh_client = R.Rule(
            params={'src': '10.1.1.1',
                    'dst': '10.1.1.2'},
            tcp={'dport': 22})
        http_client = R.Rule(
            params={'src': '10.1.1.1',
                    'dst': '10.1.1.2'},
            tcp={'dport': 80})

        rarr = R.RuleArray(ssh_client, http_client)

        lo_route = R.Rule(params={'src': '127.0.0.1',
                                  'dst': '127.0.0.1'},
                          tcp={'dport': 443})

        rarr_lo = rarr * lo_route
        rarr_no = lo_route * rarr

        for rule_lo, rule_no in zip(rarr_lo, rarr_no):
            for key in ['src', 'dst']:
                self.assertEqual(rule_lo.params[key],
                                 lo_route.params[key])
                self.assertNotEqual(rule_no.params[key],
                                    lo_route.params[key])

            self.assertEqual(rule_lo.kwargs['tcp']['dport'],
                             443)
            self.assertNotEqual(rule_no.kwargs['tcp']['dport'],
                                443)

        with self.assertRaises(TypeError):
            list() * rarr

    def testRuleArrayMatMul(self):
        """ Tests RuleArray Matrix Multiplication. """
        route_lo = R.RuleArray(
            R.Rule(
                params={'src': '127.0.0.1',
                        'dst': '127.0.0.1'}))

        route_wifi = R.RuleArray(
            R.Rule(
                params={'src': '192.168.1.0/24',
                        'dst': '192.168.1.0/24'}))

        app_ssh = R.RuleArray(
            R.Rule(
                params={'protocol': 'tcp'},
                tcp={'dport': 22}))

        app_http = R.RuleArray(
            R.Rule(
                params={'protocol': 'tcp'},
                tcp={'dport': 80}))

        with self.assertRaises(TypeError):
            route_lo * app_http

        rarr_lo_http = route_lo @ app_http
        rarr_lo_ssh = route_lo @ app_ssh
        rarr_wifi_http = route_wifi @ app_http
        rarr_wifi_ssh = route_wifi @ app_ssh
