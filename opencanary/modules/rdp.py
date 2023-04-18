import re

from opencanary.modules import CanaryService

from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory


class RemoteDesktopProtocol(Protocol):
    """
    A simple service that logs RDP connection attempts.
    Does not implement Network Level Authentication (NLA)
    """

    def dataReceived(self, data):
        # Decode the data to unicode, so we can search it, and ignore any errors
        # caused by bytes that can't be decoded.
        decoded_data = data.decode(encoding="utf-8", errors="ignore")
        # Use regex to extract the username.
        match = re.search(r"mstshash=(?P<username>[a-zA-Z0-9-_@]*)", decoded_data)
        username = match and match.groupdict().get("username")

        # Log the connection attempt
        self.factory.log(logdata={"USERNAME": username}, transport=self.transport)

        # Always respond with a negotiation failure
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/1b3920e7-0116-4345-bc45-f2c4ad012761
        self.transport.write(b"0x3 RDP_NEG_FAILURE")
        self.transport.loseConnection()


class CanaryRDP(Factory, CanaryService):
    NAME = "rdp"
    protocol = RemoteDesktopProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config, logger)
        self.port = config.getVal("rdp.port", 3389)
        self.logtype = logger.LOG_RDP


CanaryServiceFactory = CanaryRDP
