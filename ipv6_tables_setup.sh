#!/bin/sh

# Ipv6 Iptables Firewall setup script
# N.B. This script is a near copy of the ipv4 setup script.
# Only "iptables" has been changed with "ip6tables"

# INSTALL (gentoo)
# As root run this script and then the following commands
#
# rc-service ip6tables save
# rc-service ip6tables start
# rc-update add ip6tables default

# Acknowledgements
# The following sources of information were used in the making of this script

# https://www.frozentux.net/iptables-tutorial/iptables-tutorial.html
# by Oskar Andreasson

# Please note, that the following modules are required for iptables to function.
# (This is based on my current kernel setup).
# associated modules are commented on the right.
# CONFIG_PACKET=y
# CONFIG_NETFILTER=y
# CONFIG_NF_CONNTRACK=m                       #nf_conntrack, nf_conntrack_ipv4, nf_conntrack_ipv6
# CONFIG_NF_CONNTRACK_FTP=m                   #nf_conntrack_ftp
# CONFIG_NF_CONNTRACK_IRC=m                   #nf_conntrack_irc
# CONFIG_IP_NF_IPTABLES=y                     #ip_tables
# CONFIG_IP6_NF_IPTABLES=m                    #ip6_tables
# CONFIG_IP_NF_FILTER=y                       #iptable_filter
# CONFIG_IP6_NF_FILTER=m                      #ip6table_filter
# CONFIG_IP_NF_NAT=m                          #iptable_nat
# CONFIG_NETFILTER_XT_MATCH_STATE=m           #xt_state
# CONFIG_NETFILTER_XT_TARGET_LOG=m            #xt_LOG
# CONFIG_NETFILTER_XT_MATCH_LIMIT=m           #xt_limit
# CONFIG_IP_NF_TARGET_MASQUERADE=m            #ipt_MASQUERADE
# CONFIG_NETFILTER_XT_MATCH_MULTIPORT=m       #xt_multiport

# IPTABLES BINARY
IPTABLES="/sbin/ip6tables"

# SHORTHAND
INPUT="$IPTABLES -t filter --append INPUT"
OUTPUT="$IPTABLES -t filter --append OUTPUT"
FORWARD="$IPTABLES -t filter --append FORWARD"

# IMPLEMENTATION

# Before diving in ...
# Best Practices - Notes from Major Hayden
# https://major.io/2010/04/12/best-practices-iptables/

# iptable operation - rules are read from the top
#   if no matching rule is found the default policy is applied.
# default policy - set this to accept, lest you lock yourself out.
# do not blindly flush - ensure default policy is ACCEPT,
#   also consider the security implications of this
# localhost - lots of applications require lo, ensure lo is not disturbed.
# complications - split complex rules into separate chains
# reject - use REJECT until you know your rules are working properly
# stringent - be as specific as possible for your needs
# comments - use comments for obscure rules that other admins may not understand.
#  e.g. -m comment --comment "limit ssh access"
# save - Always save your rules


# Set default policy to accept to maintain current connection.
${IPTABLES} --policy INPUT ACCEPT
${IPTABLES} --policy OUTPUT ACCEPT
${IPTABLES} --policy FORWARD ACCEPT

# Flush all current iptables rules.
# and delete all user-defined chains.
${IPTABLES} --flush
${IPTABLES} --delete-chain

# Accept all local connections
${INPUT} -i lo -j ACCEPT
${OUTPUT} -o lo -j ACCEPT

# Allow established and related incoming connections
${INPUT} --protocol tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
${INPUT} --protocol udp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow the following outgoing requests for the following protocols:

# DNS
${OUTPUT} --protocol udp --dport 53 -j ACCEPT
${OUTPUT} --protocol tcp --dport 53 -j ACCEPT

# HTTP
${OUTPUT} --protocol tcp --dport 80 -j ACCEPT

# NTP
${OUTPUT} --protocol udp --dport 123 -j ACCEPT

# HTTPS
${OUTPUT} --protocol tcp --dport 443 -j ACCEPT

# SMTP
${OUTPUT} --protocol tcp --dport 587 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# CUPS / PRINTSERVER
${OUTPUT} --protocol tcp --dport 631 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# IMAP
${OUTPUT} --protocol tcp --dport 993 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# PGP KEYSERVERS
${OUTPUT} --protocol tcp --dport 11371 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# ICMP handling
${OUTPUT} --protocol icmp --icmp-type echo-request -j ACCEPT
${INPUT} --protocol icmp --icmp-type echo-reply -j ACCEPT

# Conclude
# These final rules reject anything that is not matched by the rules above
${INPUT} -j DROP
${OUTPUT} -j REJECT
${FORWARD} -j DROP
