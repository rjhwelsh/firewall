#!/usr/bin/env python3


import unittest
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
            lo_route = self.Route(
                self.Address("127.0.0.1"),
                self.Address("::1"))

    def testUnspecifiedRoutes(self):
        """ Tests setting routes with unspecified src/dst. """

        # Unspecified routes should be allowed

        # src_route
        self.Route(
            self.Address("127.0.0.1"),
            self.Address(""))

        # dst_route
        self.Route(
            self.Address(""),
            self.Address("127.0.0.1"))
