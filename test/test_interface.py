#!/usr/bin/env python3

# Unit Tests for NetworkInterface
import unittest
import baleful.interface
import subprocess


class Test_NetworkInterface(unittest.TestCase):
    netif = baleful.interface.NetworkInterface

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
            netif = self.netif("nosuchinterface")
