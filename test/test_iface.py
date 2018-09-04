#!/usr/bin/env python3

# Unit Tests for NetworkInterface
import unittest
import baleful.iface
import netifaces
import ipaddress


class Test_NetworkInterface(unittest.TestCase):
    netif = baleful.iface.NetworkInterface

    def testLoopBack(self):
        """ Verify loopback interface can be detected."""
        netif = self.netif("lo")
        self.assertEqual(netif.name, "lo")

    def testLoopBackAddress(self):
        """ Verify loopback interface can be detected."""
        netif = self.netif("lo")
        self.assertEqual(netif.addr['ip'][0]['addr'], "127.0.0.1")
        self.assertEqual(netif.addr['ip6'][0]['addr'], "::1")

    def testNoSuchInterface(self):
        """ Verify raise error on non-existent interface."""
        with self.assertRaises(ValueError):
            self.netif("nosuchinterface")

    def testRule(self):
        """ Verify rule generation. """

        gw_tuple = netifaces.gateways()[netifaces.AF_INET][0]
        gw_if = gw_tuple[1]
        gw_addr = gw_tuple[0]

        addr_tuple = netifaces.ifaddresses(gw_if)[netifaces.AF_INET][0]
        your_addr = addr_tuple['addr']
        # netmask = addr_tuple['netmask']

        netif = self.netif(gw_if)

        self.assertGreater(len(netif.rule()), 0,
                           msg="No local interface found!")

        rarr = netif.rule(chain="OUTPUT", src=1, dst=3)

        self.assertEqual(rarr[0].params['src'],
                         ipaddress.ip_network(gw_addr))
        self.assertEqual(rarr[0].params['dst'],
                         ipaddress.ip_network(your_addr))
        self.assertEqual(rarr[0].params['out_interface'],
                         gw_if)

    def testIter(self):
        """ Test network interface iteration. """

        for n, m in zip(self.netif.iter(), netifaces.interfaces()):
            self.assertEqual(n.name, m)
