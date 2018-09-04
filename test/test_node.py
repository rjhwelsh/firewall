#!/usr/bin/env python3

import unittest
from baleful.node import Node


class Test_Node(unittest.TestCase):
    """ Test case for Node class """
    def setUp(self):
        pass

    def tearDown(self):
        pass

    @unittest.skip("Root priviliges required")
    def test_set_policy(self):
        """ Tests set policy method. """
        n = Node("ponos")
        n.set_policy()
