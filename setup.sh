#!/bin/bash

# Find host file
HOST_FILE="$(readlink -e `dirname $0`)"/host.d/"$(hostname)"

[[ -x "$HOST_FILE" ]] &&
	"${HOST_FILE}" flush &&
	"${HOST_FILE}" start ||
		echo "Error! Check '${HOST_FILE}' !"
