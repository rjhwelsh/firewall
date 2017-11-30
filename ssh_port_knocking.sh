#!/bin/sh

# ssh port knocking chains setup

# This script sets up a port-knocking scheme for ssh
KNOCKS=3                       # The number of port knocks required
KNOCK_SCRIPT="knockknock.sh" # A script to initiate the knocks required for ssh access

SSHTIME=30   # No. of seconds before ssh access times out after knocking
KNOCKTIME=10 # No. of seconds before port knocking is reset back to GATE1

# Chain names
BASE="SSH"
INITIAL_CHAIN="${BASE}KNOCK"
GATE_BASENAME="${BASE}GATE"
AUTH_BASENAME="${BASE}AUTH"
PASSED_CHAIN="${BASE}PASSED"

# Acknowledgements
# Based off the tutorial below for ubuntu
# https://www.digitalocean.com/community/tutorials/how-to-configure-port-knocking-using-only-iptables-on-an-ubuntu-vps

# IPTABLES BINARY
IPTABLES="/sbin/iptables"

# SHORTHAND
INPUT="$IPTABLES -t filter --append INPUT"
OUTPUT="$IPTABLES -t filter --append OUTPUT"
FORWARD="$IPTABLES -t filter --append FORWARD"

# FUNCTIONS

# Choose random ports for knocking
# A random number between 1024 and 65535
function random_number {
	# od   = octal dump
	# -An  = --address-radix=n ; # None
	# -N4  = --read-bytes=4
	# -tu4 = --format=u4 ; # unsigned 4-byte decimal integer
	# /dev/urandom = random source
	# / 64511 ) + 1024 = port range 1024 - 65535
	echo "$[ ( $(od -An -N4 -tu4 < /dev/urandom ) / 64511 ) + 1024 ]"
}

# The knock chain
# N.B. This works backwards from the sequence of knocks
function iptable_knock_chain {
  SSHTIME="$1"
	KNOCKTIME="$2"

	# SSH ACCESS GRANTED
	AUTH="${AUTH_BASENAME}${KNOCKS}"
	${IPTABLES} -A "${INITIAL_CHAIN}" -m recent --rcheck --seconds $SSHTIME --name "${AUTH}" -j "${PASSED_CHAIN}"

	# INTERMEDIARY KNOCKS
	for no in `seq $KNOCKS -1 2`;
	do
		GATE="${GATE_BASENAME}${no}"
		AUTH="${AUTH_BASENAME}$[ ${no} - 1 ]"

		# Each authorization at a lower level provides access to a higher gate
		${IPTABLES} -A "${INITIAL_CHAIN}" -m recent --rcheck --seconds $KNOCKTIME --name "${AUTH}" -j "${GATE}"
	done

	# FIRST KNOCK
	no=1
	GATE="${GATE_BASENAME}${no}"
	# AUTH= not required ; no authorization required for the first knock
	${IPTABLES} -A "${INITIAL_CHAIN}" -j "${GATE}"

}


# A recursive iptable_rule function for port-knocks
function iptable_knock {
	NO="$1"
	PORT="$2"
	GATE="${GATE_BASENAME}${NO}"
	AUTH="${AUTH_BASENAME}${NO}"
	PRIOR_GATE="${GATE_BASENAME}$[ ${NO} - 1 ]"
	PRIOR_AUTH="${AUTH_BASENAME}$[ ${NO} - 1 ]"

	# If this is after the first knock clear the name
	[[ $NO -gt 1 ]] && ${IPTABLES} -A "${GATE}" -m recent --name "${PRIOR_AUTH}" --remove

	# If the port matches , flag it with $AUTH and then drop it.
	${IPTABLES} -A "${GATE}" -p tcp --dport $PORT -m recent --name "${AUTH}" --set -j DROP

	# Drop all other packets, or redirect to previous gateway
	[[ $NO -gt 1 ]] \
		&& ${IPTABLES} -A "${GATE}" -j "${PRIOR_GATE}" \
									 || ${IPTABLES} -A "${GATE}" -j DROP
}

# Final iptable rules for successful port knocks
function iptable_pass {
	NO="$[ $1 + 1 ]"
	PORT="$2"
	GATE="${PASSED_CHAIN}"
	# AUTH = not required
	PRIOR_GATE="${GATE_BASENAME}$[ ${NO} - 1 ]"
	PRIOR_AUTH="${AUTH_BASENAME}$[ ${NO} - 1 ]"

	# Usual flag reset
  ${IPTABLES} -A "${GATE}" -m recent --name "${PRIOR_AUTH}" --remove
	# Accept connections on ssh port
	${IPTABLES} -A "${GATE}" -p tcp --dport ${PORT} -j ACCEPT

	# Send other packets to prior gate
  ${IPTABLES} -A "${GATE}" -j "${PRIOR_GATE}"
}

function knockknock_script {
	PORT_SEQ="$1"
	NAME="$2"

	echo "#!/bin/bash" > $NAME
	echo "" >> $NAME
	echo "PORT_SEQ="'"'"${PORT_SEQ}"'"' >> $NAME
	echo 'user=$1' >> $NAME
	echo 'host=$2' >> $NAME
	echo "" >> $NAME
	echo 'for x in $PORT_SEQ' >> $NAME
	echo 'do' >> $NAME
	echo '    nmap -Pn --host_timeout 201 --max-retries 0 -p $x $host' >> $NAME
	echo '    sleep 1' >> $NAME
	echo 'done' >> $NAME
	echo 'ssh ${user}@${host}' >> $NAME
	echo "" >> $NAME
  chmod 755 $NAME

	}
# IMPLEMENTATION

# Create chains in iptables
${IPTABLES} -N "${INITIAL_CHAIN}"
${IPTABLES} -N "${PASSED_CHAIN}"

for no in `seq 1 $KNOCKS`;
do
	${IPTABLES} -N "${GATE_BASENAME}${no}"
done

# Transfer all input traffic to initial knocking chain
${INPUT} -j "${INITIAL_CHAIN}"

# Knockknock script header
PORT_SEQ=""
for no in `seq 1 $KNOCKS`;
do
	PORT=`random_number`
	PORT_SEQ="${PORT_SEQ}${PORT} "
	# Rules for knocking on ports
  iptable_knock $no $PORT
done
# Rules for allowing ssh connection in PASSED chain
iptable_pass $no 22

# Rules for knock chain
iptable_knock_chain $SSHTIME $KNOCKTIME

# Write port knocking script for ssh access
knockknock_script "${PORT_SEQ}" "${KNOCK_SCRIPT}"

# Use iptables-save to make these changes permanent
