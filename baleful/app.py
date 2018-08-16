#!/usr/bin/env python3


class Application:
    """Base class for application classes which provide details about client/server
    firewall configurations.
    """

    def __init__(self, kwarg_list):
        """ Arguments:
        A list of kwargs defining each connection
        ( Client to Server )

        Example:
        ssh:
        [ { 'dport':22, 'protocol':"tcp" } ]

        ftp-active:
        [ { 'dport':21 }, { 'sport':1027, 'ctstate':"" } ]
        N.B. Here ctstate is overridden by the application kwarg.

        """


ssh = Application([{'dport': 22, 'protocol': "tcp"}])
