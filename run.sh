#! /bin/bash

CONF="/root/opencanary.conf"
TEMP_CONF="/root/.opencanary.conf"

if [ -f $CONF ]; then
	echo "INFO: Main configuration file found"
	opencanaryd --dev
elif [ -f $TEMP_CONF ]; then
	echo "INFO: Temp configuration file found"
	opencanaryd --dev
else
	opencanaryd --copyconfig && echo "A Config file was generated at /root/.opencanary.conf. If the volume is mapped, you have a copy and should move it to /root/opencanary.conf" && echo "In either case, you can rerun this container and have it run."
fi

