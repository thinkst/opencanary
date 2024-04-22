import re

from opencanary.modules import CanaryService

from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.application import internet


class RemoteDesktopProtocol(Protocol):
    """
    A simple service that logs RDP connection attempts
    and mimics an NLA-enabled RDP server but responds with login failure
    """

    def __init__(self):
        self.initial_connection = True

    def dataReceived(self, data):
        # Decode the data to unicode, so we can search it, and ignore any errors
        # caused by bytes that can't be decoded.
        decoded_data = data.decode(encoding="utf-8", errors="ignore")
        # Use regex to extract the username.
        match = re.search(r"mstshash=(?P<username>[a-zA-Z0-9-_@]*)", decoded_data)
        username = match and match.groupdict().get("username")
        # Log the connection attempt
        self.factory.log(logdata={"USERNAME": username}, transport=self.transport)

        if self.initial_connection:
            # Respond as an NLA-enabled RDP server
            self.transport.write(
                bytes.fromhex("030000130ed000001234000209080002000000")
            )
            self.initial_connection = False
        else:
            # Always respond with a negotiation failure, details from
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/96327ab4-d43f-4803-9aff-392ce1fc2073
            self.transport.write(bytes.fromhex("0001000400010000052e"))
            self.transport.loseConnection()


class CanaryRDP(Factory, CanaryService):
    NAME = "rdp"
    protocol = RemoteDesktopProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config, logger)
        self.port = config.getVal("rdp.port", 3389)
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_RDP

    def getService(self):
        return internet.TCPServer(self.port, self, interface=self.listen_addr)


CanaryServiceFactory = CanaryRDP
