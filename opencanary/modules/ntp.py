from opencanary.modules import CanaryService

from zope.interface import implements
from twisted.application import internet
from twisted.internet.protocol import DatagramProtocol

from twisted.application.internet import UDPServer
from twisted.internet.address import IPv4Address

from twisted.internet import protocol

"""
    A log-only NTP server. It won't respond, but it will log attempts
    to trigger the MON_GETLIST_1 NTP commands, which is used for DDOS
    and network recon.
"""

class MiniNtp(DatagramProtocol):
    def datagramReceived(self, data, (host, port)):
        if len(data) < 4:
            #bogus packet, discard
            return
        logdata={'NTP CMD': 'monlist'}
        self.transport.getPeer = lambda: IPv4Address('UDP', host, port)
        self.factory.log(logdata=logdata, transport=self.transport)

class CanaryNtp(CanaryService):
    NAME = 'ntp'

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal('ntp.port', default=123))
        self.logtype = logger.LOG_NTP_MONLIST
        self.listen_addr = config.getVal('device.listen_addr', default='')

    def getService(self):
        f = MiniNtp()
        f.factory = self
        return internet.UDPServer(self.port, f, interface=self.listen_addr)
