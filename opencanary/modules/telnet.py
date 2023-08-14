from opencanary.modules import CanaryService

from twisted.application import internet
from twisted.internet.error import ConnectionDone, ConnectionLost
from twisted.internet import protocol
from twisted.cred import credentials
from twisted.conch.telnet import AuthenticatingTelnetProtocol
from twisted.conch.telnet import ITelnetProtocol
from twisted.conch.telnet import TelnetTransport
from twisted.conch.telnet import ECHO


class CanaryTelnetTransport(TelnetTransport):
    def dataReceived(self, data):
        try:
            TelnetTransport.dataReceived(self, data)
        except ValueError:
            print("Telnet client spoke weirdly, abandoning connection")
            self.loseConnection()

    def connectionLost(self, reason):
        # Avoids pointless logs on disconnect
        if reason.check(ConnectionDone) or reason.check(ConnectionLost):
            return
        TelnetTransport.connectionLost(self, reason)


class AlertAuthTelnetProtocol(AuthenticatingTelnetProtocol):
    def connectionMade(self):
        # p/Cisco telnetd/ d/router/ o/IOS/ cpe:/a:cisco:telnet/ cpe:/o:cisco:ios/a
        # NB _write() is for raw data and write() handles telnet special bytes
        self.transport._write(
            b"\xff\xfb\x01\xff\xfb\x03\xff\xfb\0\xff\xfd\0\xff\xfd\x1f\r\n"
        )
        self.transport.write(self.factory.banner)
        self.transport._write(b"User Access Verification\r\n\r\nUsername: ")

    def telnet_Password(self, line):
        # Body of this method copied from
        # twisted.conch.telnet
        username, password = self.username, line
        del self.username

        def login(ignored):
            creds = credentials.UsernamePassword(username, password)
            d = self.portal.login(creds, None, ITelnetProtocol)
            d.addCallback(self._cbLogin)
            d.addErrback(self._ebLogin)

        self.transport.wont(ECHO).addCallback(login)

        logdata = {"USERNAME": username, "PASSWORD": password}
        self.factory.canaryservice.log(logdata, transport=self.transport)
        return "Discard"


class Telnet(CanaryService):
    NAME = "telnet"

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("telnet.port", default=8023))
        self.banner = config.getVal("telnet.banner", "").encode("utf8")
        self.logtype = logger.LOG_TELNET_LOGIN_ATTEMPT
        self.listen_addr = config.getVal("device.listen_addr", default="")

        if self.banner:
            self.banner += b"\n"

    def getService(self):
        f = protocol.ServerFactory()
        f.canaryservice = self
        f.logger = self.logger
        f.banner = self.banner
        f.protocol = lambda: CanaryTelnetTransport(AlertAuthTelnetProtocol)
        return internet.TCPServer(self.port, f, interface=self.listen_addr)
