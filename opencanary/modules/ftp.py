from opencanary.modules import CanaryService

from twisted.application import internet
from twisted.protocols.ftp import FTPFactory, FTPRealm, FTP, \
                            USR_LOGGED_IN_PROCEED, GUEST_LOGGED_IN_PROCEED, IFTPShell, \
                            AuthorizationError
from twisted.cred.portal import Portal
from zope.interface import implements
from twisted.cred.checkers import ICredentialsChecker
from twisted.python import failure
from twisted.cred import error as cred_error, credentials

FTP_PATH = "/briar/data/ftp"

class DenyAllAccess:
    implements(ICredentialsChecker)

    credentialInterfaces = (credentials.IAnonymous, credentials.IUsernamePassword)

    def requestAvatarId(self, credentials):
        return failure.Failure(cred_error.UnauthorizedLogin())

class LoggingFTP(FTP):
    #ripped from main FTP class, overridden to extract connection info
    def ftp_PASS(self, password):
        """
        Second part of login.  Get the password the peer wants to
        authenticate with.
        """
        if self.factory.allowAnonymous and self._user == self.factory.userAnonymous:
            # anonymous login
            creds = credentials.Anonymous()
            reply = GUEST_LOGGED_IN_PROCEED
        else:
            # user login
            creds = credentials.UsernamePassword(self._user, password)
            reply = USR_LOGGED_IN_PROCEED

        logdata = {'USERNAME': self._user, 'PASSWORD': password}
        self.factory.canaryservice.log(logdata, transport=self.transport)

        del self._user

        def _cbLogin((interface, avatar, logout)):
            assert interface is IFTPShell, "The realm is busted, jerk."
            self.shell = avatar
            self.logout = logout
            self.workingDirectory = []
            self.state = self.AUTHED
            return reply

        def _ebLogin(failure):
            failure.trap(cred_error.UnauthorizedLogin, cred_error.UnhandledCredentials)
            self.state = self.UNAUTH
            raise AuthorizationError

        d = self.portal.login(creds, None, IFTPShell)
        d.addCallbacks(_cbLogin, _ebLogin)
        return d

class CanaryFTP(CanaryService):
    NAME = 'ftp'

    def __init__(self,config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)

        self.banner = config.getVal('ftp.banner', default='FTP Ready.').encode('utf8')
        self.port = config.getVal('ftp.port', default=21)
        # find a place to check that logtype is initialised
        # find a place to check that factory has service attached
        self.logtype = logger.LOG_FTP_LOGIN_ATTEMPT
        self.listen_addr = config.getVal('device.listen_addr', default='')

    def getService(self):
        p = Portal(FTPRealm(FTP_PATH), [DenyAllAccess()])
        f = FTPFactory(p)
        f.protocol = LoggingFTP
        f.welcomeMessage = self.banner
        f.canaryservice = self
        return internet.TCPServer(self.port, f, interface=self.listen_addr)
