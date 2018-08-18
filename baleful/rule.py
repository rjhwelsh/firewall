#!/usr/bin/env python3

import iptc


class Rule:
    """ A rule generator base class for iptc/ip6tc. """

    IPTABLES = {4: {'module': iptc,
                    'rule': iptc.Rule,
                    'table': iptc.Table},
                6: {'module': iptc,
                    'rule': iptc.Rule6,
                    'table': iptc.Table6}}

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

        self.params = params if params else dict()
        self.kwargs = kwargs if kwargs else dict()

    def __add__(self, other):
        """ Adds two rules together.
        x + y, where y values take precedence over x values. """

        params = self.params.copy()
        kwargs = self.kwargs.copy()

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
                kwargs[key] = other.kwargs[key]
            else:
                raise(ValueError("Unexpected Condition!."))

        return Rule(params=params,
                    target=other.target,
                    chain=other.chain,
                    table=other.table,
                    ipv=other.ipv,
                    **kwargs)

    def __sub__(self, other):
        """ Subtract values of one rule from another.
        x - y, where y values are removed from x. """

        params = self.params.copy()
        kwargs = self.kwargs.copy()

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

        return Rule(params=params,
                    target=self.target,
                    chain=self.chain,
                    table=self.table,
                    ipv=self.ipv,
                    **kwargs)

    def dict(self):
        """ Return a dictionary view of rule arguments. """
        kwargs = self.kwargs.copy()
        kwargs.update(
            {'': self.params.copy()})
        return kwargs

    def create(self):
        """ Returns an iptc rule """
        rule = self.IPTABLES[self.ipv]['rule']()

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
            set_methods[arg](
                str(val))

        # Set match params
        for m, params in self.kwargs.items():
            # Create match based on keyword
            match = rule.create_match(m)
            # Create arguments based on value dict.
            for arg, val in params.items():
                match.__dict__[arg] = str(val)

        return rule

    def reverse(self):
        """ Reverses the iptables rule"""

        REVERSAL_KEYS = self.__REVERSAL_KEYS

        for k0, v0 in REVERSAL_KEYS.items():
            for k1, v1 in v0.items():
                if k0 == '':
                    self.params = self.__reverse_key(k1, v1, self.params)
                elif k0 in self.kwargs:
                    self.kwargs[k0] = self.__reverse_key(
                        k1, v1, self.kwargs[k0])

        REVERSAL_VALS = self.__REVERSAL_VALS
        for k0, v0 in REVERSAL_VALS.items():
            if k0 == 'chain':
                self.chain = self.__reverse_val(self.chain, v0)
            else:
                for k1, v1 in v0.items():
                    if k0 in self.kwargs:
                        if k1 in self.kwargs[k0]:
                            value = self.kwargs[k0][k1]
                            self.kwargs[k0][k1] = self.__reverse_val(value, v1)

    # KEYS and VALUES for reverse method
    __REVERSAL_KEYS = {'': {'src': 'dst',
                            'in_interface': 'out_interface'},
                       'tcp': {'sport': 'dport'},
                       'udp': {'sport': 'dport'},
                       'iprange': {'src-range': 'dst-range'}
                       }

    __REVERSAL_VALS = {'':
                       {},
                       'chain':
                       {'INPUT': 'OUTPUT',
                        'PREROUTING': 'POSTROUTING',
                        'FORWARD': 'FORWARD'},
                       'icmp':  # k0 v0=
                       {'icmp_type':  # v0 = { k1 v1 }
                        {'echo-request': 'echo-reply'}}}

    def __reverse_key(self, skey, dkey, params):
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

    def __reverse_val(self, value, rdict):
        """ Swaps value if present in rdict. """

        if value in rdict:
            return rdict[value]
        elif value in rdict.values():
            ldict = dict((v, k) for k, v in rdict.items())
            return ldict[value]
        else:
            return value


class RuleArray(list):
    """ A rule array class for handling Rule s """

    def __init__(self, *rules):
        """Arguments:
        *rules -- Rule objects
        """

        for R in rules:
            if not isinstance(R, Rule):
                raise(TypeError(
                    "Only Rule type is allowed."))
            else:
                self.append(R)
