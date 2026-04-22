#! /bin/bash

CONF="$HOME/.opencanary/opencanary.conf"
TEMP_CONF="./opencanary.conf"

if [ -f $CONF ]; then
	echo "INFO: Main configuration file found"
	opencanary start
elif [ -f $TEMP_CONF ]; then
	echo "INFO: Temp configuration file found"
	opencanary dev
else
	opencanary copyconfig && echo "A config file was generated at $HOME/.opencanary/opencanary.conf."
fi
