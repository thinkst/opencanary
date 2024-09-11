from opencanary.modules import CanaryService

from zope.interface import implementer
from twisted.application import internet
from twisted.internet.error import ConnectionDone, ConnectionLost
from twisted.internet import protocol
from twisted.cred import portal
from twisted.cred import credentials
from twisted.conch.telnet import AuthenticatingTelnetProtocol
from twisted.conch.telnet import ITelnetProtocol
from twisted.conch.telnet import TelnetTransport
from twisted.conch.telnet import ECHO
from twisted.spread.pb import Avatar


class MyTelnet(Avatar):
    def __init__(self, name):
        self.name = name


@implementer(portal.IRealm)
class Realm:
    def requestAvatar(self, avatarId, mind, *interfaces):
        if ITelnetProtocol in interfaces:
            av = MyTelnet()
            av.state = "Command"
            return ITelnetProtocol, av, lambda: None
        raise NotImplementedError("Not supported by this realm")


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
        if self.factory.canaryservice.config.getVal(
            "telnet.log_tcp_connection", default=False
        ):
            logtype = self.factory.canaryservice.logger.LOG_TELNET_CONNECTION_MADE
            self.factory.canaryservice.log(
                {}, transport=self.transport, logtype=logtype
            )

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
        r = Realm()
        p = portal.Portal(r)
        f = protocol.ServerFactory()
        f.canaryservice = self
        f.logger = self.logger
        f.banner = self.banner
        f.protocol = lambda: CanaryTelnetTransport(AlertAuthTelnetProtocol, p)
        return internet.TCPServer(self.port, f, interface=self.listen_addr)
