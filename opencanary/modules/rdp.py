import re

from opencanary.modules import CanaryService

from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory


class RemoteDesktopProtocol(Protocol):
    """
    A simple service that logs RDP connection attempts
    and always responds with a negotiation failure
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

        # Always respond with a negotiation failure, details from
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/1b3920e7-0116-4345-bc45-f2c4ad012761
        # type (1 byte): An 8-bit, unsigned integer that indicates the packet type.
        # This field MUST be set to 0x03 (TYPE_RDP_NEG_FAILURE).
        response_type = b"\x03"
        # flags (1 byte): An 8-bit, unsigned integer that contains protocol flags.
        # There are currently no defined flags, so the field MUST be set to 0x00.
        flags = b"\x00"
        # length (2 bytes): A 16-bit, unsigned integer that specifies the packet size.
        # This field MUST be set to 0x0008 (8 bytes).
        length = b"\x00\x08"
        # failureCode (4 bytes): A 32-bit, unsigned integer that specifies the failure code.
        # We use SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER
        failure_code = b"\x00\x00\x00\x06"
        self.transport.write(response_type + flags + length + failure_code)
        self.transport.loseConnection()


class CanaryRDP(Factory, CanaryService):
    NAME = "rdp"
    protocol = RemoteDesktopProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config, logger)
        self.port = config.getVal("rdp.port", 3389)
        self.logtype = logger.LOG_RDP


CanaryServiceFactory = CanaryRDP
