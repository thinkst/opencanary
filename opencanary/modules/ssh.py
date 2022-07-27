
from opencanary.modules import CanaryService
import twisted
from twisted.cred import portal, checkers, credentials, error
from twisted.conch import error, avatar, interfaces as conchinterfaces
from twisted.conch.checkers import SSHPublicKeyDatabase
from twisted.conch.ssh import factory, userauth, connection, keys, session, transport
from twisted.conch.openssh_compat import primes
from twisted.conch.ssh.common import MP
from twisted.internet import reactor, protocol, defer
from twisted. application import internet

from zope.interface import implementer
import sys, os, time
import base64, struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa

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
            key = "Invalid SSH Public Key Submitted: {key_blob}".format(key_blob=key_blob.hex())
            for keytype in [b'ecdsa-sha2-nistp256',b'ecdsa-sha2-nistp384',b'ecdsa-sha2-nistp521',b'ssh-ed25519']:
                if keytype in key_blob:
                    key = '{keytype} {keydata}'.format(
                            keytype=keytype,
                            keydata=base64.b64encode(key_blob))

            print('Key was {key}'.format(key=key))

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
        b'ssh-userauth': HoneyPotSSHUserAuthServer,
        b'ssh-connection': connection.SSHConnection,
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
        _modulis = '/etc/ssh/moduli', '/private/etc/moduli'

        if self.version:
            t.ourVersionString = self.version
        else:
            t.ourVersionString = 'empty'

        t.supportedPublicKeys = self.privateKeys.keys()
        for _moduli in _modulis:
            try:
                self.primes = primes.parseModuliFile(_moduli)
                break
            except IOError:
                pass

        if not self.primes:
            ske = t.supportedKeyExchanges[:]
            if 'diffie-hellman-group-exchange-sha1' in ske:
                ske.remove('diffie-hellman-group-exchange-sha1')
            t.supportedKeyExchanges = ske

        t.factory = self
        return t


@implementer(portal.IRealm)
class HoneyPotRealm:

    def __init__(self):
        pass

    def requestAvatar(self, avatarId, mind, *interfaces):
        if conchinterfaces.IConchUser in interfaces:
            return interfaces[0], \
                HoneyPotAvatar(avatarId, self.env), lambda: None
        else:
            raise Exception("No supported interfaces found.")

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
        isLibssh = data.find(b'libssh', data.find(b'SSH-')) != -1

        if (twisted.version.major < 11 or isLibssh) and \
                not self.hadVersion and self.gotVersion:
            self.sendKexInit()
            self.hadVersion = True

    def ssh_KEXINIT(self, packet):
        #print('Remote SSH version: %s' % (self.otherVersionString,))
        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)

    def ssh_KEX_DH_GEX_REQUEST(self, packet):
        MSG_KEX_DH_GEX_GROUP = 31
        #We have to override this method since the original will
        #pick the client's ideal DH group size. For some SSH clients, this is
        #8192 bits, which takes minutes to compute. Instead, we pick the minimum,
        #which on our test client was 1024.
        if self.ignoreNextPacket:
            self.ignoreNextPacket = 0
            return
        self.dhGexRequest = packet
        min, ideal, max = struct.unpack('>3L', packet)
        self.g, self.p = self.factory.getDHPrime(min)
        self.sendPacket(MSG_KEX_DH_GEX_GROUP, MP(self.p) + MP(self.g))

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
        if not 'bad packet length' in desc.decode():
            # With python >= 3 we can use super?
            transport.SSHServerTransport.sendDisconnect(self, reason, desc)
        else:
            self.transport.write('Protocol mismatch.\n')
            log.msg('Disconnecting with error, code %s\nreason: %s' % \
                (reason, desc))
            self.transport.loseConnection()

class HoneyPotSSHSession(session.SSHSession):
    def request_env(self, data):
        #print('request_env: %s' % (repr(data)))
        pass


@implementer(conchinterfaces.ISession)
class HoneyPotAvatar(avatar.ConchUser):

    def __init__(self, username, env):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.env = env
        self.channelLookup.update({'session': HoneyPotSSHSession})

    def openShell(self, protocol):
        return

    def getPty(self, terminal, windowSize, attrs):
        return None

    def execCommand(self, protocol, cmd):
        return

    def closed(self):
        pass

    def eofReceived(self):
        pass

    def windowChanged(self, windowSize):
        self.windowSize = windowSize


def getRSAKeys():
    """
    Checks for existing RSA Keys, if there are none, generates a 2048 bit
    RSA key pair, saves them to a temporary location and returns the keys
    formatted as OpenSSH keys.
    """
    public_key = os.path.join(SSH_PATH, 'id_rsa.pub')
    private_key = os.path.join(SSH_PATH, 'id_rsa')

    if not (os.path.exists(public_key) and os.path.exists(private_key)):
        ssh_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend())
        public_key_string = ssh_key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH)
        private_key_string = ssh_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption())
        with open(public_key, 'w+b') as key_file:
            key_file.write(public_key_string)

        with open(private_key, 'w+b') as key_file:
            key_file.write(private_key_string)
    else:
        with open(public_key) as key_file:
            public_key_string = key_file.read()
        with open(private_key) as key_file:
            private_key_string = key_file.read()

    return public_key_string, private_key_string


def getDSAKeys():
    """
    Checks for existing DSA Keys, if there are none, generates a 2048 bit
    DSA key pair, saves them to a temporary location and returns the keys
    formatted as OpenSSH keys.
    """
    public_key = os.path.join(SSH_PATH, 'id_dsa.pub')
    private_key = os.path.join(SSH_PATH, 'id_dsa')

    if not (os.path.exists(public_key) and os.path.exists(private_key)):
        ssh_key = dsa.generate_private_key(
            key_size=1024,
            backend=default_backend())
        public_key_string = ssh_key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH)
        private_key_string = ssh_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption())
        with open(public_key, 'w+b') as key_file:
            key_file.write(public_key_string)
        with open(private_key, 'w+b') as key_file:
            key_file.write(private_key_string)
    else:
        with open(public_key) as key_file:
            public_key_string = key_file.read()
        with open(private_key) as key_file:
            private_key_string = key_file.read()

    return public_key_string, private_key_string


@implementer(checkers.ICredentialsChecker)
class HoneypotPasswordChecker:

    credentialInterfaces = (credentials.IUsernamePassword,)

    def __init__(self, logger=None):
        self.logger = logger
        self.auth_attempt = 0


    def requestAvatarId(self, credentials):
        return defer.fail(error.UnauthorizedLogin())


@implementer(checkers.ICredentialsChecker)
class CanaryPublicKeyChecker:

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
        factory.publicKeys = {b'ssh-rsa': keys.Key.fromString(data=rsa_pubKeyString),
                              b'ssh-dss': keys.Key.fromString(data=dsa_pubKeyString)}
        factory.privateKeys = {b'ssh-rsa': keys.Key.fromString(data=rsa_privKeyString),
                               b'ssh-dss': keys.Key.fromString(data=dsa_privKeyString)}
        return internet.TCPServer(self.port, factory, interface=self.listen_addr)
