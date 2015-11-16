from opencanary.modules import CanaryService

from zope.interface import implements
from twisted.conch.telnet import TelnetTransport, AuthenticatingTelnetProtocol
from twisted.application import internet
from twisted.internet.protocol import ServerFactory
from twisted.application.internet import TCPServer

from twisted.internet import protocol
from twisted.cred import portal
from twisted.cred import credentials
from twisted.conch.telnet import AuthenticatingTelnetProtocol
from twisted.conch.telnet import ITelnetProtocol
from twisted.conch.telnet import TelnetTransport
from twisted.conch.telnet import ECHO

class Realm:
    implements(portal.IRealm)
    
    def requestAvatar(self, avatarId, mind, *interfaces):
        if ITelnetProtocol in interfaces:
            av = MyTelnet()
            av.state = 'Command'
            return ITelnetProtocol, av, lambda:None
        raise NotImplementedError("Not supported by this realm")

class AlertAuthTelnetProtocol(AuthenticatingTelnetProtocol):
    def connectionMade(self):
        # p/Cisco telnetd/ d/router/ o/IOS/ cpe:/a:cisco:telnet/ cpe:/o:cisco:ios/a
        # NB _write() is for raw data and write() handles telnet special bytes
        self.transport._write("\xff\xfb\x01\xff\xfb\x03\xff\xfb\0\xff\xfd\0\xff\xfd\x1f\r\n")
        self.transport.write(self.factory.banner)
        self.transport._write("User Access Verification\r\n\r\nUsername: ")

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

        logdata = {'USERNAME': username, 'PASSWORD': password}
        self.factory.canaryservice.log(logdata, transport=self.transport)
        return 'Discard'

class Telnet(CanaryService):
    NAME = 'telnet'

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal('telnet.port', default=8023))
        self.banner = config.getVal('telnet.banner', '').encode('utf8')
        self.logtype = logger.LOG_TELNET_LOGIN_ATTEMPT
        self.listen_addr = config.getVal('device.listen_addr', default='')

        if self.banner:
            self.banner += "\n"

    def getService(self):
        r = Realm()
        p = portal.Portal(r)
        f = protocol.ServerFactory()
        f.canaryservice = self
        f.logger = self.logger
        f.banner = self.banner
        f.protocol = lambda: TelnetTransport(AlertAuthTelnetProtocol, p)
        return internet.TCPServer(self.port, f, interface=self.listen_addr)
