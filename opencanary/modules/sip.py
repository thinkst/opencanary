from opencanary.modules import CanaryService

from zope.interface import implements
from twisted.application import internet
from twisted.internet.protocol import DatagramProtocol
from twisted.protocols.sip import Base

from twisted.application.internet import UDPServer
from twisted.internet.address import IPv4Address

from twisted.internet import protocol

"""
    A log-only SIP server. It won't respond, but it will log any
    SIP requests sent its way.
"""

class SIPServer(Base):
    def handle_request(self, request, addr):
        try:
            logdata={'HEADERS': request.headers.data}
            self.transport.getPeer = lambda: IPv4Address('UDP', addr[0], addr[1])
            self.factory.log(logdata=logdata, transport=self.transport)
        except Exception as e:
            self.factory.log(logdata={'ERROR': e}, transport=self.transport)

class CanarySIP(CanaryService):
    NAME = 'SIP'

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal('sip.port', default=5060))
        self.logtype=self.logger.LOG_SIP_REQUEST
        self.listen_addr = config.getVal('device.listen_addr', default='')


    def getService(self):
        f = SIPServer()
        f.factory = self
        return internet.UDPServer(self.port, f, interface=self.listen_addr)
