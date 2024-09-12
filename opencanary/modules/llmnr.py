from opencanary.modules import CanaryService
from twisted.application import internet
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.address import IPv4Address
from twisted.internet import reactor
from scapy.all import IP, UDP, send, DNS
from scapy.layers.dns import DNSQR
from scapy.layers.llmnr import LLMNRQuery
import random


class LLMNR(DatagramProtocol):
    def startQueryLoop(self):
        self.sendLLMNRQuery()
        next_interval = self.factory.query_interval + random.uniform(
            -self.factory.query_splay, self.factory.query_splay
        )
        reactor.callLater(next_interval, self.startQueryLoop)

    def sendLLMNRQuery(self):
        # Craft an LLMNR query packet
        target_ip = "224.0.0.252"  # LLMNR multicast IP address
        target_port = 5355  # LLMNR port
        llmnr_packet = (
            IP(dst=target_ip, ttl=1)
            / UDP(dport=target_port)
            / LLMNRQuery(qd=DNSQR(qname=self.factory.query_hostname))
        )

        # Send the packet, set verbose to False to suppress "Sent 1 packet" std-out
        send(llmnr_packet, verbose=False)

    def datagramReceived(self, data, host_and_port):
        try:
            llmnr_response = DNS(data)
            # Decode bytes to string and remove trailing dot if present
            received_hostname = llmnr_response.qd.qname.decode("utf-8").rstrip(".")
            # If the received hostname matches the canary hostname, it's suspicous - log it
            if received_hostname == self.factory.query_hostname:
                source_ip = host_and_port[0]
                logdata = {
                    "query_hostname": self.factory.query_hostname,
                    "response": llmnr_response.summary(),
                }
                self.transport.getPeer = lambda: IPv4Address(
                    "UDP", source_ip, host_and_port[1]
                )
                self.factory.log(
                    logdata=logdata,
                    transport=self.transport,
                    logtype=self.factory.logtype_query_response,
                )

        except Exception as e:
            error_message = f"Error processing LLMNR response: {e}"
            self.factory.log(error_message, level="error")


class CanaryLLMNR(CanaryService):
    NAME = "llmnr"

    def __init__(self, config=None, logger=None):
        super(CanaryLLMNR, self).__init__(config=config, logger=logger)
        self.logtype_query_response = logger.LOG_LLMNR_QUERY_RESPONSE
        self.query_hostname = config.getVal("llmnr.hostname", default="DC03")
        self.port = int(config.getVal("llmnr.port", default=5355))
        self.query_interval = int(
            config.getVal("llmnr.query_interval", default=60)
        )  # Interval in seconds
        self.query_splay = int(
            config.getVal("llmnr.query_splay", default=5)
        )  # Default splay in seconds
        self.listen_addr = config.getVal("device.listen_addr", default="")

    def getService(self):
        f = LLMNR()
        f.factory = self
        reactor.callWhenRunning(f.startQueryLoop)
        return internet.UDPServer(self.port, f, interface=self.listen_addr)
