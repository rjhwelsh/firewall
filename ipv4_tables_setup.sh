#!/bin/sh

# Ipv4 Iptables Firewall setup script

# INSTALL (gentoo)
# As root run this script and then the following commands
#
# rc-service iptables save
# rc-service iptables start
# rc-update add iptables default

# Pesky programs that interfere with iptables themselves.
# rc-service libvirtd
# virsh net-list --all                  # list all networks
# virsh net-destroy default             # shutdown network
# virsh net-autostart --disable default # disable autostart
# virsh net-undefine default            # permanently remove network

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
# CONFIG_NF_CONNTRACK_SIP=m                   #nf_conntrack_sip
#
# In gentoo modules to load can be set in /etc/conf.d/modules

# IPTABLES BINARY
IPTABLES="/sbin/iptables"

# SHORTHAND
INPUT="$IPTABLES -t filter --append INPUT"
OUTPUT="$IPTABLES -t filter --append OUTPUT"
FORWARD="$IPTABLES -t filter --append FORWARD"

HOST_IP="192.168.1.1"
CLIENT_IP="${HOST_IP}/24"
INTERFACE="eth0"
LAN_IN="${INPUT} -s ${CLIENT_IP} -d ${HOST_IP} -i ${INTERFACE}"
LAN_OUT="${OUTPUT} -d ${CLIENT_IP} -s ${HOST_IP} -o ${INTERFACE}"

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

# Ethernet
# DHCP assign to anonymous
${INPUT} -i enp12s0 --protocol udp --sport 68 --dport 67 -j ACCEPT
${OUTPUT} -o enp12s0 --protocol udp --sport 67 --dport 68 -j ACCEPT
# DHCP receive from anonymous
${INPUT} -i enp12s0 --protocol udp --sport 67 --dport 68 -j ACCEPT
${OUTPUT} -o enp12s0 --protocol udp --sport 68 --dport 67 -j ACCEPT

# All other connections

# Allow incoming, outgoing connections for distcc
# daemon is disabled by default
# (potential security hole)
${OUTPUT} -d ${CLIENT_IP} --protocol tcp --sport 3632 -j ACCEPT
${INPUT} -s ${CLIENT_IP} --protocol tcp --dport 3632 -j ACCEPT

# Allow established and related incoming connections
${INPUT} --protocol tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
${INPUT} --protocol udp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow the following outgoing requests for the following protocols:

# DNS
${OUTPUT} --protocol udp --dport 53 -j ACCEPT
${OUTPUT} --protocol tcp --dport 53 -j ACCEPT

# Avahi zeroconf
${INPUT} --protocol udp --dport 5353 -j ACCEPT
${OUTPUT} --protocol udp --sport 5353 -j ACCEPT

# FTP
${OUTPUT} --protocol tcp --dport 21 -j ACCEPT

# HTTP
${OUTPUT} --protocol tcp --dport 80 -j ACCEPT

# NTP
${OUTPUT} --protocol udp --dport 123 -j ACCEPT

# HTTPS
${OUTPUT} --protocol tcp --dport 443 -j ACCEPT

# SMTP
${OUTPUT} --protocol tcp --dport 587 -j ACCEPT

# CUPS / PRINTSERVER
${OUTPUT} --protocol tcp --dport 631 -j ACCEPT
${OUTPUT} --protocol tcp --sport 631 -j ACCEPT

# RSYNC
${OUTPUT} --protocol tcp --dport 873 -j ACCEPT

# IMAP
${OUTPUT} --protocol tcp --dport 993 -j ACCEPT

# PGP KEYSERVERS
${OUTPUT} --protocol tcp --dport 11371 -j ACCEPT

# SIP

# Sip server ports
${OUTPUT} --protocol tcp --dport 5060 -j ACCEPT
${OUTPUT} --protocol udp --dport 5060 -j ACCEPT

  # Stun server access
${OUTPUT} --protocol udp --dport 3478 -j ACCEPT
${OUTPUT} --protocol tcp --dport 3478 -j ACCEPT

   # Audio RTP port
${OUTPUT} --protocol udp --dport 7076:7079 -j ACCEPT

   # Video RTP port
${OUTPUT} --protocol udp --dport 9076:9079 -j ACCEPT

# IRC and similar chat clients
   # Google hangouts
${OUTPUT} --protocol tcp --dport 5222 -j ACCEPT
   # IRC (including ssl support)
${OUTPUT} --protocol tcp --dport 6667 -j ACCEPT
${OUTPUT} --protocol tcp --dport 6697 -j ACCEPT
${OUTPUT} --protocol tcp --dport 7000 -j ACCEPT

# Hedgewars - Turn Based Strategy Game
# Multiplayer Server Port
${OUTPUT} --protocol tcp --sport 46631 -j ACCEPT
${INPUT} --protocol tcp --dport 46631 -j ACCEPT
# Multiplayer Client
${OUTPUT} --protocol tcp --dport 46631 -j ACCEPT

# ICMP handling
${OUTPUT} --protocol icmp --icmp-type echo-request -j ACCEPT
${INPUT} --protocol icmp --icmp-type echo-reply -j ACCEPT

# BIT-TORRENT (rtorrent in/out 49173)
# ${OUTPUT} --protocol tcp --sport 49173 -j ACCEPT
# ${INPUT} --protocol tcp --dport 49173 -j ACCEPT
# Just use : /sbin/iptables --flush OUTPUT
# This will allow all outgoing connections,
# After a connection is established - rebuild the firewall by running $0
# OR maybe rebuild the firewall after downloading your torrent

# SSH PORT allow out and knocking sequence
${OUTPUT} --protocol tcp --dport 22 -j ACCEPT # Allow outgoing ssh to go out
${OUTPUT} --protocol tcp --sport 22 -j ACCEPT # Allow incoming ssh to go out
source ./ssh_port_knocking.sh

# Conclude
# These final rules reject anything that is not matched by the rules above
${INPUT} -j DROP
${OUTPUT} -j REJECT
${FORWARD} -j DROP
