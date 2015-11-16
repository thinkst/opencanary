from opencanary.modules import CanaryService

from zope.interface import implements
from twisted.application import internet
from twisted.internet.protocol import DatagramProtocol

from twisted.application.internet import UDPServer
from twisted.internet.address import IPv4Address

from twisted.internet import protocol

"""
    A log-only Tftp server. It won't respond, but it will log attempts
    to either read or write files.
"""

class Tftp(DatagramProtocol):
    def datagramReceived(self, data, (host, port)):
        if len(data) < 5:
            #bogus packet, discard
            return

        if data[:2] == "\x00\x01":
            opcode="READ"
        elif data[:2] == "\x00\x02":
            opcode="WRITE"
        else:
            #don't log other opcodes
            return

        try:
            (filename, mode, ignore) = data[2:].split("\x00")
        except ValueError:
            return

        logdata={'FILENAME': filename, 'OPCODE': opcode, 'MODE': mode}
        self.transport.getPeer = lambda: IPv4Address('UDP', host, port)
        self.factory.log(logdata=logdata, transport=self.transport)

class CanaryTftp(CanaryService):
    NAME = 'tftp'

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal('tftp.port', default=69))
        self.logtype=self.logger.LOG_TFTP
        self.listen_addr = config.getVal('device.listen_addr', default='')


    def getService(self):
        f = Tftp()
        f.factory = self
        return internet.UDPServer(self.port, f, interface=self.listen_addr)
