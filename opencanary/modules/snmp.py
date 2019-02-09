from opencanary.modules import CanaryService

from twisted.application import internet
from twisted.internet.protocol import DatagramProtocol

from twisted.internet.address import IPv4Address

from scapy.all import SNMP
"""
    A log-only SNMP server. It won't respond, but it will log SNMP queries.
"""

class MiniSNMP(DatagramProtocol):
    def datagramReceived(self, data, host_and_port):
        try:
            snmp = SNMP(data)
            community = snmp.community.val
            requests = [x.oid.val for x in snmp.PDU.varbindlist]

            logdata={'REQUESTS': requests, 'COMMUNITY_STRING': community}
            self.transport.getPeer = lambda: IPv4Address('UDP', host_and_port[0], host_and_port[1])
            self.factory.log(logdata=logdata, transport=self.transport)
        except Exception as e:
            print(e)
            pass


class CanarySNMP(CanaryService):
    NAME = 'SNMP'

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal('snmp.port', default=161))
        self.logtype = logger.LOG_SNMP_CMD
        self.listen_addr = config.getVal('device.listen_addr', default='')

    def getService(self):
        f = MiniSNMP()
        f.factory = self
        return internet.UDPServer(self.port, f, interface=self.listen_addr)
