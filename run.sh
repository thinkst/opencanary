#! /bin/bash

CONF="/etc/opencanary/opencanary.conf"
TEMP_CONF="/etc/opencanary/.opencanary.conf"

if [ -f $CONF ]; then
	echo "INFO: Main configuration file found"
	opencanary start
elif [ -f $TEMP_CONF ]; then
	echo "INFO: Temp configuration file found"
	opencanary dev
else
	opencanary copyconfig && echo "A Config file was generated at /etc/opencanary/.opencanary.conf."
fi
