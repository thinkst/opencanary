FROM python:3.6-buster

WORKDIR /root/

RUN apt update &&\
	 apt-get install -y sudo vim build-essential libssl-dev libffi-dev python-dev libpcap-dev
RUN pip install rdpy
RUN pip install opencanary
RUN pip install scapy pcapy 
COPY run.sh /bin/run
RUN chmod +x /bin/run

CMD /bin/run

