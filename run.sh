#! /bin/bash

CONF="/etc/opencanaryd/opencanary.conf"
TEMP_CONF="/etc/opencanaryd/.opencanary.conf"

if [ -f $CONF ]; then
	echo "INFO: Main configuration file found"
	opencanaryd --start
elif [ -f $TEMP_CONF ]; then
	echo "INFO: Temp configuration file found"
	opencanaryd --dev
else
	opencanaryd --copyconfig && echo "A Config file was generated at /etc/opencanaryd/.opencanary.conf."
fi

