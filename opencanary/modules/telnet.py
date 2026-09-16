from opencanary.modules import CanaryService

from zope.interface import implementer
from twisted.application import internet
from twisted.internet import reactor
from twisted.internet.error import ConnectionDone, ConnectionLost
from twisted.cred import portal
from twisted.cred import credentials
from twisted.conch.telnet import AuthenticatingTelnetProtocol
from twisted.conch.telnet import ITelnetProtocol
from twisted.conch.telnet import TelnetTransport
from twisted.conch.telnet import ECHO
from twisted.protocols.policies import LimitTotalConnectionsFactory, TimeoutMixin
from twisted.python.compat import iterbytes
from twisted.spread.pb import Avatar

DEFAULT_MAX_CONNECTIONS = 64
DEFAULT_TIMEOUT = 120
MAX_SUBNEGOTIATION_BYTES = 256
SUBNEGOTIATION_LIMIT_ERROR = "Telnet subnegotiation buffer limit reached"


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


class CanaryTelnetTransport(TimeoutMixin, TelnetTransport):
    def connectionMade(self):
        TelnetTransport.connectionMade(self)
        self.setTimeout(self.factory.timeout)

    def callLater(self, period, func):
        return getattr(self.factory, "reactor", reactor).callLater(period, func)

    def dataReceived(self, data):
        self.resetTimeout()

        try:
            for byte in iterbytes(data):
                TelnetTransport.dataReceived(self, byte)
                if (
                    self.state.startswith("subnegotiation")
                    and len(self.commands) >= MAX_SUBNEGOTIATION_BYTES
                ):
                    self.factory.canaryservice.log(
                        {"ERROR": SUBNEGOTIATION_LIMIT_ERROR},
                        transport=self.transport,
                    )
                    self.commands = []
                    self.setTimeout(None)
                    self.loseConnection()
                    return
        except ValueError:
            print("Telnet client spoke weirdly, abandoning connection")
            self.setTimeout(None)
            self.loseConnection()

    def timeoutConnection(self):
        self.setTimeout(None)
        self.loseConnection()

    def connectionLost(self, reason):
        self.setTimeout(None)
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
        self.max_connections = int(
            config.getVal("telnet.max_connections", default=DEFAULT_MAX_CONNECTIONS)
        )
        self.timeout = float(config.getVal("telnet.timeout", default=DEFAULT_TIMEOUT))
        self.reactor = reactor
        self.logtype = logger.LOG_TELNET_LOGIN_ATTEMPT
        self.listen_addr = config.getVal("device.listen_addr", default="")

        if self.banner:
            self.banner += b"\n"

    def getService(self):
        r = Realm()
        p = portal.Portal(r)
        f = LimitTotalConnectionsFactory()
        f.connectionLimit = self.max_connections
        f.connectionCount = 0
        f.timeout = self.timeout
        f.reactor = self.reactor
        f.canaryservice = self
        f.logger = self.logger
        f.banner = self.banner
        f.protocol = lambda: CanaryTelnetTransport(AlertAuthTelnetProtocol, p)
        return internet.TCPServer(self.port, f, interface=self.listen_addr)
