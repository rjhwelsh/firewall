#!/usr/bin/env python3

import iptc
import ipaddress


class Rule:
    """ A rule generator base class for iptc/ip6tc. """

    IPTABLES = {4: {'module': iptc,
                    'rule': iptc.Rule,
                    'table': iptc.Table,
                    'chain': iptc.Chain,
                    'addr': ipaddress.IPv4Network},
                6: {'module': iptc,
                    'rule': iptc.Rule6,
                    'table': iptc.Table6,
                    'chain': iptc.Chain,
                    'addr': ipaddress.IPv6Network}}

    WILD_ADDR = {4: "0.0.0.0/0.0.0.0",
                 6: "::/128"}

    DEFAULTS = {'target': "ACCEPT",
                'chain': "OUTPUT",
                'table': "FILTER",
                'ipv': 4}

    def __init__(self,
                 params=None,
                 target=None,
                 chain=None,
                 table=None,
                 ipv=None,
                 **kwargs):
        """Keyword Arguments:
        params -- iptc rule parameters (dict)
        target -- the target of the rule (str)
        chain -- the chain to put the rule in (str)
        table -- the table to put the rule in (str)
        ipv -- The inet version 4 or 6 (int)
        **kwargs    -- iptc match module parameters (dict)

        Example:
        params := { 'protocol': "tcp", src: "::1" }
        tcp = { dport:80, sport: ... }
        mark = { ... }
        """

        for key, val in self.DEFAULTS.items():
            if isinstance(locals()[key], type(None)):
                self.__dict__[key] = val
            else:
                self.__dict__[key] = locals()[key]

        self.params = self.__conv_params(params)
        self.kwargs = kwargs if kwargs else dict()

    def __default_params(self):
        """ Returns the default params. """
        params = {'src': self.IPTABLES[self.ipv]['addr'](
            self.WILD_ADDR[self.ipv]),
            'dst': self.IPTABLES[self.ipv]['addr'](
            self.WILD_ADDR[self.ipv]),
            'in_interface': None,
            'out_interface': None,
            'protocol': 'ip'}

        if self.ipv == 4:
            params['fragment'] = False

        return params

    def __conv_params(self, params):
        """ Converts params to  relevant objects.
            src, dst -> ip_network objects
        """
        all_params = self.__default_params()
        if params:
            for key, val in params.items():
                if key in ['src', 'dst']:
                    params[key] = self.IPTABLES[self.ipv]['addr'](val)
            all_params.update(params)
        return all_params

    def __add__(self, other):
        """ Adds two rules together.
        x + y, x.__add__(y)
        where y values update x values. """

        if not isinstance(other, type(self)):
            raise(TypeError)

        rule = self.copy()
        params = rule.params
        kwargs = rule.kwargs

        rule.target = other.target
        rule.chain = other.chain
        rule.table = other.table
        rule.ipv = other.ipv

        params.update(other.params)

        kwarg_keys = set(
            [k for k in kwargs] +
            [k for k in other.kwargs])

        for key in kwarg_keys:
            if key in kwargs and key in other.kwargs:
                kwargs[key].update(other.kwargs[key])
            elif key in kwargs:
                pass
            elif key in other.kwargs:
                kwargs[key] = other.kwargs[key].copy()
            else:
                raise(ValueError("Unexpected Condition!."))

        return rule

    def __sub__(self, other):
        """ Subtract values of one rule from another.
        x - y, where y values are removed from x. """

        if not isinstance(other, type(self)):
            raise(TypeError)

        rule = self.copy()
        params = rule.params
        kwargs = rule.kwargs

        def diff(x, y):
            """ x -- dict, y -- dict
            x - y """
            p = list()
            for k, v in x.items():
                if k in y and v == y[k]:
                    p.append(k)

            for i in p:
                x.pop(i)
            return x

        params = diff(params, other.params)

        for key in kwargs:
            kwargs[key] = diff(kwargs[key], other.kwargs[key])

        return rule

    def dict(self):
        """ Return a dictionary view of rule arguments. """
        kwargs = self.kwargs.copy()
        kwargs.update(
            {'': self.params.copy()})
        return kwargs

    def __str_dict(self, kwargs):
        """ Converts a dictionary into string arguments for comparison. """
        for k1, v1 in kwargs.items():
            for k2, v2 in v1.items():
                kwargs[k1][k2] = str(v2)

        return kwargs

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            raise(TypeError)

        if (self.__str_dict(self.dict()) == self.__str_dict(other.dict())):
            return True
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __contains__(self, rule):
        """ Returns True, if self is a superset of 'rule' """
        general_rule = self.__str_dict(self.dict())
        general_defaults = self.__default_params()
        specific_rule = rule.__str_dict(rule.dict())

        for k1, v1 in general_rule.items():
            for k2, v2 in v1.items():
                if not ((k1 == '') and (v2 == str(general_defaults[k2]))):
                    if (k1 not in specific_rule or
                            k2 not in specific_rule[k1] or
                            not specific_rule[k1][k2] == v2):
                        return False

        return True

    def copy(self):
        """ Returns a copy of a Rule. """
        params = self.params.copy()
        kwargs = {k: v.copy()
                  for k, v in self.kwargs.items()}
        return Rule(params=params,
                    target=self.target,
                    chain=self.chain,
                    table=self.table,
                    ipv=self.ipv,
                    **kwargs)

    def flip(self):
        """ Flips the iptables rule"""

        FLIP_KEYS = self.__FLIP_KEYS

        for k0, v0 in FLIP_KEYS.items():
            for k1, v1 in v0.items():
                if k0 == '':
                    self.params = self.__flip_key(k1, v1, self.params)
                elif k0 in self.kwargs:
                    self.kwargs[k0] = self.__flip_key(
                        k1, v1, self.kwargs[k0])

        FLIP_VALS = self.__FLIP_VALS
        for k0, v0 in FLIP_VALS.items():
            if k0 == 'chain':
                self.chain = self.__flip_val(self.chain, v0)
            else:
                for k1, v1 in v0.items():
                    if k0 in self.kwargs:
                        if k1 in self.kwargs[k0]:
                            value = self.kwargs[k0][k1]
                            self.kwargs[k0][k1] = self.__flip_val(value, v1)

    # KEYS and VALUES for flip method
    __FLIP_KEYS = {'': {'src': 'dst',
                        'in_interface': 'out_interface'},
                   'tcp': {'sport': 'dport'},
                   'udp': {'sport': 'dport'},
                   'iprange': {'src-range': 'dst-range'}}

    __FLIP_VALS = {'':
                   {},
                   'chain':
                   {'INPUT': 'OUTPUT',
                    'PREROUTING': 'POSTROUTING',
                    'FORWARD': 'FORWARD'},
                   'icmp':  # k0 v0=
                   {'icmp_type':  # v0 = { k1 v1 }
                    {'echo-request': 'echo-reply'}}}

    def __flip_key(self, skey, dkey, params):
        """ Swaps keys over for a parameter dictionary. """

        if skey in params and dkey in params:
            holdkey = params[skey]
            params[skey] = params[dkey]
            params[dkey] = holdkey

        elif skey in params and dkey not in params:
            params[dkey] = params.pop(skey)

        elif dkey in params and skey not in params:
            params[skey] = params.pop(dkey)

        elif skey not in params and dkey not in params:
            pass

        else:
            raise(ValueError("Unexpected condition!"))

        return params

    def __flip_val(self, value, rdict):
        """ Swaps value if present in rdict. """

        if value in rdict:
            return rdict[value]
        elif value in rdict.values():
            ldict = dict((v, k) for k, v in rdict.items())
            return ldict[value]
        else:
            return value

    def _iptc_table(self):
        """ Returns the iptc table. """
        tableName = self.table
        tableClass = self.IPTABLES[self.ipv]['table']
        return tableClass(
            tableClass.__dict__[tableName])

    def _iptc_chain(self):
        """ Returns the iptc chain. """
        chainName = self.chain
        chainClass = self.IPTABLES[self.ipv]['chain']

        return chainClass(
            self._iptc_table(),
            chainName)

    def iptc(self):
        """ Returns an iptc rule """

        ruleClass = self.IPTABLES[self.ipv]['rule']
        rule = ruleClass(
            chain=self._iptc_chain())

        # Setup method table
        set_methods = {'src': rule.set_src,
                       'dst': rule.set_dst,
                       'in_interface': rule.set_in_interface,
                       'out_interface': rule.set_out_interface,
                       'fragment': rule.set_fragment,
                       'protocol': rule.set_protocol}

        # Set target
        rule.create_target(self.target)

        # Set rule params
        for arg, val in self.params.items():
            if arg in ['src',
                       'dst',
                       'in_interface',
                       'out_interface']:
                if val:
                    set_methods[arg](str(val))
            else:
                set_methods[arg](val)

        # Set match params
        for m, params in self.kwargs.items():
            # Create match based on keyword
            match = rule.create_match(m)
            # Create arguments based on value dict.
            for arg, val in params.items():
                match.set_parameter(arg, str(val))
        return rule

    @classmethod
    def from_iptc(cls, rule):
        """ Converts from iptc.Rule into a baleful.Rule object. """

        for key, value in cls.IPTABLES.items():
            if isinstance(rule, value['rule']):
                ipv = key
                break

        kwargs = dict()
        for match in rule.matches:
            key = match.name
            kwargs[key] = dict()

            for prop, val in match.get_all_parameters().items():
                kwargs[key][prop] = ','.join(val)

        return Rule(params={'src': rule.get_src(),
                            'dst': rule.get_dst(),
                            'in_interface': rule.get_in_interface(),
                            'out_interface': rule.get_out_interface(),
                            'fragment': rule.get_fragment(),
                            'protocol': rule.get_protocol()},
                    ipv=ipv,
                    chain=rule.chain.name,
                    table=rule.chain.table.name.upper(),
                    target=rule.target.name,
                    **kwargs)

    def __iptc_rule_iter(self):
        """ Iterates over rules for a particular chain."""
        chain = self._iptc_chain()
        for rule in chain.rules:
            yield rule

    def exists(self):
        """ Returns whether the rule exists in the current chain."""
        chain = self._iptc_chain()
        rule = self.iptc()

        if rule in chain.rules:
            return True
        return False

    def matches(self):
        """ Returns rules that match this ruleset."""
        chain = self._iptc_chain()

        for rule in chain.rules:
            brule = self.from_iptc(rule)
            if brule in self:
                yield brule


class RuleArray(list):
    """ A rule array class for handling Rules """

    def __init__(self, *rules: Rule):
        """Arguments:
        *rules -- Rule objects
        """

        for R in rules:
            if not isinstance(R, Rule):
                raise(TypeError(
                    "Only type(Rule) is allowed."))
            else:
                self.append(R)

    def copy(self):
        """ Returns a copy of the Rule Array. """
        newArray = RuleArray()
        for R in self:
            newArray.append(R.copy())
        return newArray

    def __rmul__(self, other: Rule):
        """ Adds a rule with every item in Array.
        y * x_arr = z_arr, where values in x_arr take precedence. """
        rarr = self.copy()
        for i, r in enumerate(rarr):
            rarr[i] = other + r
        return rarr

    def __mul__(self, other: Rule):
        """ Adds a rule with every item in Array. """
        rarr = self.copy()
        for i, r in enumerate(rarr):
            rarr[i] = r + other
        return rarr

    def __matmul__(self, other: list):
        """ Matrix multiplication between two rule arrays. """
        newArray = RuleArray()
        for i in self:
            for j in other:
                newArray.append(i + j)
        return newArray

    def __rtruediv__(self, other: Rule):
        """ Removes every item in Array from a rule. """
        rule = other.copy()
        for r in self:
            rule -= r
        return rule

    def __truediv__(self, other: Rule):
        """ Removes a rule from every item in Array. """
        rarr = self.copy()
        for i, r in enumerate(rarr):
            rarr[i] -= other
        return rarr
