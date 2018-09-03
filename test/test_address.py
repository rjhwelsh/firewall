#!/usr/bin/env python3


import unittest
import ipaddress
import baleful.address


class Test_Address(unittest.TestCase):
    Address = baleful.address.Address

    def testLoopBackAddr(self):
        """ Tests basic Address functionality. """
        lo_addr = self.Address("127.0.0.1")
        self.assertEqual(str(lo_addr), "127.0.0.1")


class Test_Route(unittest.TestCase):
    Address = baleful.address.Address
    Route = baleful.address.Route

    def testLoopBackRoute(self):
        """ Tests loopback Route functionality. """
        lo_route = self.Route(
            self.Address("127.0.0.1"),
            self.Address("127.0.0.1"))

        self.assertEqual(str(lo_route), "127.0.0.1 -> 127.0.0.1")

    def testIpv46MixingRaises(self):
        """ Tests mixing ipv4 ipv6 addresses raises error."""
        with self.assertRaises(ValueError):
            self.Route(
                self.Address("127.0.0.1"),
                self.Address("::1"))

    def testUnspecifiedRoutes(self):
        """ Tests setting routes with unspecified src/dst. """

        # Unspecified routes should be allowed
        # They should not create values in the rule

        src_route = self.Route(
            self.Address("127.0.0.1"),
            self.Address(""))

        self.assertEqual(src_route.params['dst'], ipaddress.ip_network(
            "0.0.0.0/0"))

        dst_route = self.Route(
            self.Address(""),
            self.Address("127.0.0.1"))

        self.assertEqual(dst_route.params['src'], ipaddress.ip_network(
            "0.0.0.0/0"))
