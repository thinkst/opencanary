FROM python:3.6-buster

RUN apt update &&\
	 apt-get install -y sudo vim build-essential libssl-dev libffi-dev python-dev &&\
	 apt-get install -y libpcap-dev && apt-get install -y build-essential libssl-dev libffi-dev python-dev

RUN pip install rdpy
RUN pip install opencanary
RUN pip install scapy pcapy 

CMD opencanaryd --start && tail -f /var/tmp/opencanary.log


