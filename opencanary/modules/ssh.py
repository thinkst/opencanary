from opencanary.modules import CanaryService

import twisted
from twisted.cred import portal, checkers, credentials, error
from twisted.conch import error, avatar, interfaces as conchinterfaces
from twisted.conch.checkers import SSHPublicKeyDatabase
from twisted.conch.ssh import factory, userauth, connection, keys, session, transport
from twisted.internet import reactor, protocol, defer
from twisted. application import internet

from zope.interface import implements
import sys, os, time
import base64

SSH_PATH="/var/tmp"

#pulled from Kippo
from twisted.conch.ssh.common import NS, getNS
class HoneyPotSSHUserAuthServer(userauth.SSHUserAuthServer):
    def serviceStarted(self):
        userauth.SSHUserAuthServer.serviceStarted(self)

        us = self.transport.getHost()
        peer = self.transport.getPeer()

        logdata = {'LOCALVERSION': self.transport.ourVersionString, 'REMOTEVERSION': self.transport.otherVersionString}
        logtype = self.transport.factory.canaryservice.logger.LOG_SSH_REMOTE_VERSION_SENT
        log = self.transport.factory.canaryservice.log
        log(logdata,
            logtype=logtype,
            src_host=peer.address.host,
            src_port=peer.address.port,
            dst_host=us.address.host,
            dst_port=us.address.port
        )

        self.bannerSent = False

    def sendBanner(self):
        if self.bannerSent:
            return
        data = ''
        data = '\r\n'.join(data.splitlines() + [''])
        self.transport.sendPacket(
            userauth.MSG_USERAUTH_BANNER, NS(data) + NS('en'))
        self.bannerSent = True

    def auth_password(self, packet):
        """
        Password authentication.  Payload::
            string password

        Make a UsernamePassword credential and verify it with our portal.
        """
        password = getNS(packet[1:])[0]
        c = credentials.UsernamePassword(self.user, password)

        us = self.transport.getHost()
        peer = self.transport.getPeer()

        logdata = {'USERNAME': self.user, 'PASSWORD': password, 'LOCALVERSION': self.transport.ourVersionString, 'REMOTEVERSION': self.transport.otherVersionString}
        logtype =  self.transport.factory.canaryservice.logger.LOG_SSH_LOGIN_ATTEMPT

        log = self.transport.factory.canaryservice.log
        log(logdata,
            logtype=logtype,
            src_host=peer.address.host,
            src_port=peer.address.port,
            dst_host=us.address.host,
            dst_port=us.address.port)

        return self.portal.login(c, None, conchinterfaces.IConchUser).addErrback(
                                                        self._ebPassword)

    def auth_publickey(self, packet):

        try:
            #extract the public key blob from the SSH packet
            key_blob = getNS(getNS(packet[1:])[1])[0]
        except:
            key_blob = "No public key found."

        try:
            #convert blob into openssh key format
            key = keys.Key.fromString(key_blob).toString('openssh')
        except:
            key = "Invalid SSH Public Key Submitted: {key_blob}".format(key_blob=key_blob.encode('hex'))
            for keytype in ['ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521','ssh-ed25519']:
                if keytype in key_blob:
                    key = '{keytype} {keydata}'.format(
                            keytype=keytype,
                            keydata=base64.b64encode(key_blob))

            print 'Key was {key}'.format(key=key)

        c = credentials.SSHPrivateKey(None,None,None,None,None)

        #self.log(key=key)

        return self.portal.login(c, None, conchinterfaces.IConchUser).addErrback(
                                                        self._ebPassword)

    def ssh_USERAUTH_REQUEST(self, packet):
        self.sendBanner()
        return userauth.SSHUserAuthServer.ssh_USERAUTH_REQUEST(self, packet)

# As implemented by Kojoney
class HoneyPotSSHFactory(factory.SSHFactory):
    services = {
        'ssh-userauth': HoneyPotSSHUserAuthServer,
        'ssh-connection': connection.SSHConnection,
        }

    # Special delivery to the loggers to avoid scope problems
    def logDispatch(self, sessionid, msg):
        data = {}
        data['logdata'] = msg
        self.logger.log(data)
        #for dblog in self.dbloggers:
        #    dblog.logDispatch(sessionid, msg)

    def __init__(self, logger=None, version=None):
        # protocol^Wwhatever instances are kept here for the interact feature
        self.sessions = {}
        self.logger = logger
        self.version = version

    def buildProtocol(self, addr):
        # FIXME: try to mimic something real 100%
        t = HoneyPotTransport()

        if self.version:
            t.ourVersionString = self.version
        else:
            t.ourVersionString = 'empty'

        t.supportedPublicKeys = self.privateKeys.keys()

        if not self.primes:
            ske = t.supportedKeyExchanges[:]
            ske.remove('diffie-hellman-group-exchange-sha1')
            t.supportedKeyExchanges = ske

        t.factory = self
        return t

class HoneyPotRealm:
    implements(portal.IRealm)

    def __init__(self):
        pass

    def requestAvatar(self, avatarId, mind, *interfaces):
        if conchinterfaces.IConchUser in interfaces:
            return interfaces[0], \
                HoneyPotAvatar(avatarId, self.env), lambda: None
        else:
            raise Exception, "No supported interfaces found."

class HoneyPotTransport(transport.SSHServerTransport):

    hadVersion = False

    def connectionMade(self):
        logdata = {'SESSION': str(self.transport.sessionno)}
        logtype = self.factory.canaryservice.logger.LOG_SSH_NEW_CONNECTION
        log = self.factory.canaryservice.log
        log(logdata, transport=self.transport, logtype=logtype)

        self.interactors = []
        self.logintime = time.time()
        self.ttylog_open = False
        transport.SSHServerTransport.connectionMade(self)

    def sendKexInit(self):
        # Don't send key exchange prematurely
        if not self.gotVersion:
            return
        transport.SSHServerTransport.sendKexInit(self)

    def dataReceived(self, data):
        transport.SSHServerTransport.dataReceived(self, data)
        # later versions seem to call sendKexInit again on their own
        isLibssh = data.find('libssh', data.find('SSH-')) != -1

        if (twisted.version.major < 11 or isLibssh) and \
                not self.hadVersion and self.gotVersion:
            self.sendKexInit()
            self.hadVersion = True

    def ssh_KEXINIT(self, packet):
        #print 'Remote SSH version: %s' % (self.otherVersionString,)
        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)

    def lastlogExit(self):
        starttime = time.strftime('%a %b %d %H:%M',
            time.localtime(self.logintime))
        endtime = time.strftime('%H:%M',
            time.localtime(time.time()))
        duration = str((time.time() - self.logintime))
        clientIP = self.transport.getPeer().host
        #print('root\tpts/0\t%s\t%s - %s (%s)' % \
        #    (clientIP, starttime, endtime, duration))

    # this seems to be the only reliable place of catching lost connection
    def connectionLost(self, reason):
        for i in self.interactors:
            i.sessionClosed()
        if self.transport.sessionno in self.factory.sessions:
            del self.factory.sessions[self.transport.sessionno]
        #self.lastlogExit()
        if self.ttylog_open:
            ttylog.ttylog_close(self.ttylog_file, time.time())
            self.ttylog_open = False
        transport.SSHServerTransport.connectionLost(self, reason)

    def sendDisconnect(self, reason, desc):
        """
        Workaround for the "bad packet length" error message.

        @param reason: the reason for the disconnect.  Should be one of the
                       DISCONNECT_* values.
        @type reason: C{int}
        @param desc: a descrption of the reason for the disconnection.
        @type desc: C{str}
        """
        if not 'bad packet length' in desc:
            # With python >= 3 we can use super?
            transport.SSHServerTransport.sendDisconnect(self, reason, desc)
        else:
            self.transport.write('Protocol mismatch.\n')
            log.msg('Disconnecting with error, code %s\nreason: %s' % \
                (reason, desc))
            self.transport.loseConnection()

class HoneyPotSSHSession(session.SSHSession):
    def request_env(self, data):
        #print 'request_env: %s' % (repr(data))
        pass

class HoneyPotAvatar(avatar.ConchUser):
    implements(conchinterfaces.ISession)

    def __init__(self, username, env):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.env = env
        self.channelLookup.update({'session': HoneyPotSSHSession})

        #userdb = core.auth.UserDB()
        #self.uid = self.gid = userdb.getUID(self.username)

        #if not self.uid:
        #    self.home = '/root'
        #else:
        #    self.home = '/home/' + username

    def openShell(self, protocol):
        #serverProtocol = core.protocol.LoggingServerProtocol(
        #    core.protocol.HoneyPotInteractiveProtocol, self, self.env)
        #serverProtocol.makeConnection(protocol)
        #protocol.makeConnection(session.wrapProtocol(serverProtocol))
        return

    def getPty(self, terminal, windowSize, attrs):
        #print 'Terminal size: %s %s' % windowSize[0:2]
        #self.windowSize = windowSize
        return None

    def execCommand(self, protocol, cmd):
        #cfg = config()
        #if not cfg.has_option('honeypot', 'exec_enabled') or \
        #        cfg.get('honeypot', 'exec_enabled').lower() not in \
        #            ('yes', 'true', 'on'):
        #    print 'Exec disabled. Not executing command: "%s"' % cmd
        #    raise core.exceptions.NotEnabledException, \
        #        'exec_enabled not enabled in configuration file!'
#            return


        #print 'exec command: "%s"' % cmd
        #serverProtocol = kippo.core.protocol.LoggingServerProtocol(
        #    kippo.core.protocol.HoneyPotExecProtocol, self, self.env, cmd)
        #serverProtocol.makeConnection(protocol)
        #protocol.makeConnection(session.wrapProtocol(serverProtocol))

        return

    def closed(self):
        pass

    def eofReceived(self):
        pass

    def windowChanged(self, windowSize):
        self.windowSize = windowSize

def getRSAKeys():
    public_key = os.path.join(SSH_PATH, 'id_rsa.pub')
    private_key = os.path.join(SSH_PATH, 'id_rsa')

    if not (os.path.exists(public_key) and os.path.exists(private_key)):
        from Crypto.PublicKey import RSA
        from twisted.python import randbytes
        KEY_LENGTH = 2048
        rsaKey = RSA.generate(KEY_LENGTH, randbytes.secureRandom)
        publicKeyString = keys.Key(rsaKey).public().toString('openssh')
        privateKeyString = keys.Key(rsaKey).toString('openssh')
        with file(public_key, 'w+b') as f:
            f.write(publicKeyString)
        with file(private_key, 'w+b') as f:
            f.write(privateKeyString)
    else:
        with file(public_key) as f:
            publicKeyString = f.read()
        with file(private_key) as f:
            privateKeyString = f.read()
    return publicKeyString, privateKeyString

def getDSAKeys():
    public_key = os.path.join(SSH_PATH, 'id_dsa.pub')
    private_key = os.path.join(SSH_PATH, 'id_dsa')

    if not (os.path.exists(public_key) and os.path.exists(private_key)):
        from Crypto.PublicKey import DSA
        from twisted.python import randbytes
        KEY_LENGTH = 1024
        dsaKey = DSA.generate(KEY_LENGTH, randbytes.secureRandom)
        publicKeyString = keys.Key(dsaKey).public().toString('openssh')
        privateKeyString = keys.Key(dsaKey).toString('openssh')
        with file(public_key, 'w+b') as f:
            f.write(publicKeyString)
        with file(private_key, 'w+b') as f:
            f.write(privateKeyString)
    else:
        with file(public_key) as f:
            publicKeyString = f.read()
        with file(private_key) as f:
            privateKeyString = f.read()
    return publicKeyString, privateKeyString

class HoneypotPasswordChecker:
    implements(checkers.ICredentialsChecker)

    credentialInterfaces = (credentials.IUsernamePassword,)

    def __init__(self, logger=None):
        self.logger = logger
        self.auth_attempt = 0


    def requestAvatarId(self, credentials):
        return defer.fail(error.UnauthorizedLogin())

class CanaryPublicKeyChecker:
    implements(checkers.ICredentialsChecker)

    credentialInterfaces = (credentials.ISSHPrivateKey,)

    def __init__(self, logger=None):
        self.logger = logger
        self.auth_attempt = 0

    def requestAvatarId(self, credentials):
        return defer.fail(error.UnauthorizedLogin())

class CanarySSH(CanaryService):
    NAME = 'ssh'

    def __init__(self,config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("ssh.port", default=22))
        self.version = config.getVal("ssh.version", default="SSH-2.0-OpenSSH_5.1p1 Debian-5").encode('utf8')
        self.listen_addr = config.getVal('device.listen_addr', default='')

    def getService(self):
        factory = HoneyPotSSHFactory(version=self.version, logger=self.logger)
        factory.canaryservice = self
        factory.portal = portal.Portal(HoneyPotRealm())

        rsa_pubKeyString, rsa_privKeyString = getRSAKeys()
        dsa_pubKeyString, dsa_privKeyString = getDSAKeys()
        factory.portal.registerChecker(HoneypotPasswordChecker(logger=factory.logger))
        factory.portal.registerChecker(CanaryPublicKeyChecker(logger=factory.logger))
        factory.publicKeys = {'ssh-rsa': keys.Key.fromString(data=rsa_pubKeyString),
                              'ssh-dss': keys.Key.fromString(data=dsa_pubKeyString)}
        factory.privateKeys = {'ssh-rsa': keys.Key.fromString(data=rsa_privKeyString),
                               'ssh-dss': keys.Key.fromString(data=dsa_privKeyString)}
        return internet.TCPServer(self.port, factory, interface=self.listen_addr)
