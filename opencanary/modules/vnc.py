from opencanary.modules import CanaryService

from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.application import internet

from opencanary.modules.des import des

import os

RFB_33  = '003.003'
RFB_37  = '003.007'
RFB_38  = '003.008'

#states
PRE_INIT = 1
HANDSHAKE_SEND = 2
SECURITY_SEND = 3
AUTH_SEND = 4
AUTH_OVER = 5

#if one of these is used in the VNC authentication attempt, alert that 
#a common password was tried
COMMON_PASSWORDS=['111111', 'password', '123456', '111111','1234',
                  'administrator','root','passw0rd']

class ProtocolError(Exception):
    pass

class UnsupportedVersion(Exception):
    pass

class VNCProtocol(Protocol):
    """
        Implementation of VNC up to VNC authentication
    """
    def __init__(self, version=RFB_38):
        self.serv_version = version
        self.state = PRE_INIT

    def _send_handshake(self,):
        print('send handshake')
        self.transport.write('RFB {version}\n'.format(version=self.serv_version))
        self.state = HANDSHAKE_SEND

    def _recv_handshake(self,data=None):
        print('got handshake')
        if len(data) != 12 or data[:3] != 'RFB':
            raise ProtocolError()
        client_ver = data[4:-1]

        #support single version for now
        if client_ver != RFB_38:
            raise UnsupportedVersion()

        self._send_security()

    def _send_security(self,):
        print('send security')
        self.transport.write('\x01\x02')#VNC authentication
        self.state = SECURITY_SEND

    def _recv_security(self,data=None):
        print('got security')
        if len(data) != 1 and data != '\x02':
            raise ProtocolError()
        self._send_auth()

    def _send_auth(self,):
        print('send auth')
        self.challenge = os.urandom(16)
        self.transport.write(self.challenge)
        self.state = AUTH_SEND

    def _recv_auth(self,data=None):
        print('got auth')
        if len(data) != 16:
            raise ProtocolError()
        logdata = {"VNC Server Challenge" : self.challenge.encode('hex'),
                   "VNC Client Response": data.encode('hex')}

        used_password = self._try_decrypt_response(response=data)
        if used_password:
            logdata['VNC Password'] = used_password
        else:
            logdata['VNC Password'] = '<Password was not in the common list>'
        self.factory.log(logdata, transport=self.transport)
        self._send_auth_failed()

    def connectionMade(self):
        if self.state != PRE_INIT:
            raise ProtocolError()
        self._send_handshake()

    def _send_auth_failed(self,):
        self.transport.write('\x00\x00\x00\x01'+#response code
                             '\x00\x00\x00\x16'+#message length
                             'Authentication failure')#Message
        self.state = AUTH_OVER
        raise ProtocolError()

    def _try_decrypt_response(self, response=None):
        #attempt to decrypt each of the common passwords
        #really inefficient, but it means we don't have to rely on
        #a static challenge
        for password in COMMON_PASSWORDS:
            pw = password[:8]#vnc passwords are max 8 chars
            if len(pw) < 8:
                pw+= '\x00'*(8-len(pw))

            #VNC use of DES requires password bits to be mirrored
            pw = ''.join([chr(int('{:08b}'.format(ord(x))[::-1], 2))
                                                       for x in pw])
            desbox = des(pw)
            decrypted_challenge = desbox.decrypt(response)
            if decrypted_challenge == self.challenge:
                return password
        return None

    def dataReceived(self, data):
        """
        Recieved data is unbuffered so we buffer it for telnet.
        """
        try:
            if self.state == HANDSHAKE_SEND:
                self._recv_handshake(data=data)
            elif self.state == SECURITY_SEND:
                self._recv_security(data=data)
            elif self.state == AUTH_SEND:
                self._recv_auth(data=data)
        except (UnsupportedVersion, ProtocolError):
            self.transport.loseConnection()
            return

class CanaryVNC(Factory, CanaryService):
    NAME = 'VNC'
    protocol = VNCProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config, logger)
        self.port = config.getVal("vnc.port", 5900)
        self.logtype = logger.LOG_VNC

CanaryServiceFactory = CanaryVNC
