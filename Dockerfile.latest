FROM python:3.6-buster

RUN mkdir -p /opencanary

COPY bin /opencanary/bin
COPY data /opencanary/data
COPY opencanary /opencanary/opencanary
COPY docs /opencanary/docs
COPY LICENSE /opencanary/LICENSE
COPY requirements.txt /opencanary/requirements.txt
COPY setup.py /opencanary/setup.py

WORKDIR /opencanary

RUN pip install -r requirements.txt

