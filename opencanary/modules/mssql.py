from opencanary.modules import CanaryService
from opencanary.config import ConfigException

from twisted.protocols.policies import TimeoutMixin
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.application import internet
from ntlmlib.messages import ChallengeResponse, TargetInfo

import struct
import re
import collections

# Monkeypatch bug in ntmllib
if getattr(TargetInfo, 'getData', None) is None:
    def getData(self):
        return self.get_data()
    TargetInfo.getData = getData

TDSPacket = collections.namedtuple('TDSPacket', 'type status spid packetid window payload')
PreLoginOption = collections.namedtuple('PreLoginOption', 'token data')

class MSSQLProtocol(Protocol, TimeoutMixin):
    # overview https://msdn.microsoft.com/en-us/library/dd357422.aspx

    TDS_HEADER_LEN = 8
    TDS_TYPE_PRELOGIN = 0x12
    TDS_TYPE_RESPONSE = 0x04
    TDS_TYPE_LOGIN7 = 0x10
    TDS_TYPE_SSPI = 0x11

    # https://msdn.microsoft.com/en-us/library/dd357559.aspx
    PRELOGIN_VERSION = 0x00
    PRELOGIN_ENCRYPTION = 0x01
    PRELOGIN_INSTOPT = 0x02
    PRELOGIN_THREADID = 0x03
    PRELOGIN_MARS = 0x04
    PRELOGIN_TRACEID = 0x05
    PRELOGIN_FEDAUTHREQUIRED = 0x06
    PRELOGIN_NONCEOPT = 0x07

    # https://msdn.microsoft.com/en-us/library/dd304019.aspx
    LOGIN7_OPT1_BYTEORDER_MASK = 0x01
    LOGIN7_OPT1_BYTEORDER_X86 = 0x01
    LOGIN7_OPT1_BYTEORDER_68000 = 0x01
    LOGIN7_FIELDS = ["length", "TDSversion", "packetSize", "clientProgVer", "clientPID", "connID", "optFlags1", "optFlags2", "typeFlags", "optFlags3", "clientTimeZone", "clientLCID", "ibHostName", "cchHostName", "ibUserName", "cchUserName", "ibPassword", "cchPassword", "ibAppName", "cchAppName", "ibServerName", "cchServerName", "ibExtension", "cbExtension", "ibCltIntName", "cchCltIntName", "ibLanguage", "cchLanguage", "ibDatabase", "cchDatabase", "ClientID", "ibSSPI", "cbSSPI", "ibAtchDBFile", "cchAtchDBFile", "ibChangePassword", "cchChangePassword", "cbSSPILong"]

    NMAP_PROBE_1 = TDSPacket(
        type=18,
        status=1,
        spid=0,
        packetid=0,
        window=0,
        payload='\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00(\x00\x04\xff\x08\x00\x01U\x00\x00\x00MSSQLServer\x00H\x0f\x00\x00')

    NMAP_PROBE_1_RESP = {
        "2008R2" : "\x04\x01\x00.\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x32\x10\xb4",
        "2012" : "\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0b\x00\x0c\x38",
        "2014" : "\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0c\x00\x07\xd0"
    }

    def __init__(self, factory):
        self._busyReceiving = False
        self._buffer = ""
        self.factory = factory
        self.setTimeout(10)

    @staticmethod
    def build_packet(tds):
        header = struct.pack('>BBHHBB',
                             tds.type,
                             tds.status,
                             len(tds.payload) + MSSQLProtocol.TDS_HEADER_LEN,
                             tds.spid,
                             tds.packetid,
                             tds.window
        )

        return  header + tds.payload

    @staticmethod
    def parsePreLogin(data):
        # parse the initial packet
        index = data.find("\xff")

        if index <= 0:
            return None

        options = data[:index]

        if (len(options) % 5 != 0):
            return None

        def getOption(i):
            (token, offset, length) = struct.unpack(">BHH", options[i:i+5])
            tokendata = data[offset: offset + length]
            assert(len(tokendata) == length)
            return PreLoginOption._make((token, tokendata))

        try:
            return map(getOption, range(0, len(options), 5))
        except Exception as e:
            print(e)

        return None

    @staticmethod
    def buildPreLogin(preloginopts):
        preloginopts.sort(key=lambda x: x.token)
        dataoffset = len(preloginopts) * 5 + len("\xff")
        data = ""
        header = ""

        for opt in preloginopts:
            token = opt.token
            offset = dataoffset + len(data)
            length = len(opt.data)
            header += struct.pack(">BHH", token, offset, length)
            data += opt.data

        return header + "\xff" +  data

    @staticmethod
    def parseLogin7(data):
        # These header values apper to be little endian, even though
        # the byte-order flag suggests otherwise. In case it is
        # dependent, simply check the endian flag in optFlags1 in
        # before parsing the rest in ord(data[24]). For the moment,
        # we'll assume that flag applies only to the data part.
        hfmt = "< 6I 4B l I 18H 6s 6H I"
        hlen = struct.calcsize(hfmt)
        try:
            htuple = struct.unpack(hfmt, data[:hlen])
        except Exception as e:
            return None

        def decodePassChar(c):
            # https://msdn.microsoft.com/en-us/library/dd304019.aspx
            c = ord(c) ^ 0xa5
            return chr(((c & 0x0F) << 4) | (c >> 4))

        fields = {}
        for (i, fieldname) in enumerate(MSSQLProtocol.LOGIN7_FIELDS):
            fields[fieldname] = htuple[i]

        loginData = {}
        for field in "HostName UserName Password AppName ServerName Language Database CltIntName".split():
            try:
                findex = fields["ib" + field]
                flen = fields["cch" + field] * 2 # this is character count, not count of bytes
                _fdata = data[findex: findex + flen]
                if field == "Password":
                    _fdata = "".join(map(decodePassChar, _fdata))
                loginData[field] = _fdata.decode('utf-16')
            except Exception as e:
                pass

        field="SSPI"
        findex = fields["ib" + field]
        flen = fields["cb" + field]
        if flen == 0:
            return loginData
        loginData["NTLM"] = data[findex: findex + flen]
        return loginData

    @staticmethod
    def buildError(msgtxt, serverName, procName=""):
        tokentype = 0xAA
        number = 18456
        state = 1
        sevclass = 14
        msgtxtlen= len(msgtxt)
        serverNameLen=len(serverName)
        procNameLen=len(procName)
        lineNumber=1

        msgtxt = msgtxt.encode('utf-16le')
        procName = procName.encode('utf-16le')
        serverName = serverName.encode('utf-16le')

        # This length works, but tests seem show mssql 2014 uses an (incorrect?) length -3 bytes shorter than this
        length = 4 + 1 + 1 + 2 + 1 + 1 + 4 + 2 + 1 + len(msgtxt) + len(serverName) + len(procName)

        fmt="<BHlBB H%ds B%ds B%ds l" % (len(msgtxt), len(serverName), len(procName))

        data = struct.pack(fmt, tokentype, length, number, state, sevclass, msgtxtlen, msgtxt, serverNameLen, serverName, procNameLen, procName, lineNumber)

        return data

    def consume_packet(self):
        """ Consume TDS packet off buffer"""
        hlen = MSSQLProtocol.TDS_HEADER_LEN
        if len(self._buffer) < hlen:
            return None

        try:
            header = list(struct.unpack('>BBHHBB', self._buffer[:hlen]))
            plen = header[2]
            del header[2]
            if len(self._buffer) >= plen:
                payload = self._buffer[hlen: plen]
                self._buffer = self._buffer[plen:]
                tds = TDSPacket._make(header  + [payload])
                return tds
            else:
                # Whole payload not yet recieved. Leave header in
                # buffer but return copy of header anyway
                return TDSPacket._make(header + [None])
        except Exception as e:
            print(e)

        return None

    @staticmethod
    def buildChallengeToken():
        spnegoheader='\xa1\x82\x01Y0\x82\x01U\xa0\x03\n\x01\x01\xa1\x0c\x06\n+\x06\x01\x04\x01\x827\x02\x02\n\xa2\x82\x01>\x04\x82\x01:'

        # This NTLMSSP challenge is a modified actual challenge
        # stripped using the ntlmlib:
        #
        # # do dynamic patch above to fix ntlmlib bug if nec
        # c = Challenge()
        # c.from_string(raw_str)
        # # c['target_name'] = "yoyoma".encode('utf-16le')
        # del c['target_info'].fields[3]
        # del c['target_info'].fields[4]
        # c['target_info_len'] = ''
        # template = c.get_data()
        old = 'NTLMSSP\x00\x02\x00\x00\x00\x1e\x00\x1e\x008\x00\x00\x00\x15\xc2\x8a\xe26Ph\x8a\xae\x84R\xbe@\xd5qt\xe4\x00\x00\x00\xe4\x00\xe4\x00V\x00\x00\x00\x06\x02\xf0#\x00\x00\x00\x0fW\x00I\x00N\x002\x00K\x001\x002\x00-\x00D\x00O\x00M\x00A\x00I\x00N\x00S\x00\x02\x00\x1e\x00W\x00I\x00N\x002\x00K\x001\x002\x00-\x00D\x00O\x00M\x00A\x00I\x00N\x00S\x00\x01\x00\x1e\x00W\x00I\x00N\x002\x00K\x001\x002\x00-\x00D\x00O\x00M\x00A\x00I\x00N\x00S\x00\x04\x00D\x00w\x00i\x00n\x002\x00k\x001\x002\x00-\x00d\x00o\x00m\x00a\x00i\x00n\x00s\x00r\x00v\x00.\x00c\x00o\x00r\x00p\x00.\x00t\x00h\x00i\x00n\x00k\x00s\x00t\x00.\x00c\x00o\x00m\x00\x03\x00D\x00w\x00i\x00n\x002\x00k\x001\x002\x00-\x00d\x00o\x00m\x00a\x00i\x00n\x00s\x00r\x00v\x00.\x00c\x00o\x00r\x00p\x00.\x00t\x00h\x00i\x00n\x00k\x00s\x00t\x00.\x00c\x00o\x00m\x00\x07\x00\x08\x00\xa2\x9e\xda\x91\x1f\xbb\xd0\x01\x00\x00\x00\x00\x06\x02\xf0#\x00\x00\x00\x0fy\x00o\x00y\x00o\x00m\x00a\x00\x00\x00\x00\x00'

        template = 'NTLMSSP\x00\x02\x00\x00\x00\x1e\x00\x1e\x008\x00\x00\x00\x15\xc2\x8a\xe26Ph\x8a\xae\x84R\xbe@\xd5qt\xe4\x00\x00\x00\x06\x02\xf0#\x00\x00\x00\x0fW\x00I\x00N\x002\x00K\x001\x002\x00-\x00D\x00O\x00M\x00A\x00I\x00N\x00S\x00\x07\x00\x08\x00\xa2\x9e\xda\x91\x1f\xbb\xd0\x01\x00\x00\x00\x00'

        payload = spnegoheader + old
        return "\xed" + struct.pack("<H",len(payload)) + payload

    def process(self,tds):
        if tds.payload is None:
            return

        if tds == MSSQLProtocol.NMAP_PROBE_1:
            self.transport.write(MSSQLProtocol.NMAP_PROBE_1_RESP[self.factory.canaryservice.version])

        elif tds.type == MSSQLProtocol.TDS_TYPE_PRELOGIN:
            rPreLogin = [
                PreLoginOption(MSSQLProtocol.PRELOGIN_VERSION, '\x0c\x00\x10\x04\x00\x00'),
                PreLoginOption(MSSQLProtocol.PRELOGIN_ENCRYPTION, '\x02'),
                PreLoginOption(MSSQLProtocol.PRELOGIN_INSTOPT, '\x00'),
                PreLoginOption(MSSQLProtocol.PRELOGIN_THREADID, ''),
                PreLoginOption(MSSQLProtocol.PRELOGIN_MARS, '\x00'),
                PreLoginOption(MSSQLProtocol.PRELOGIN_TRACEID, '')
            ]

            payload = self.buildPreLogin(rPreLogin)

            rtds = TDSPacket(
                type=MSSQLProtocol.TDS_TYPE_RESPONSE,
                status=0x01,
                spid=0x00,
                packetid=0x01,
                window=0x00,
                payload=payload
            )
            self.transport.write(self.build_packet(rtds))

        elif tds.type == MSSQLProtocol.TDS_TYPE_LOGIN7:
            loginData = self.parseLogin7(tds.payload)
            if loginData is None:
                self.transport.abortConnection()

            errormsg = ""
            servername = ""
            ntlm = loginData.pop('NTLM', None)
            if ntlm is not None:
                # TODO: handle NTLM challenge generation correctly
                errormsg = "Login failed."
                logdata = {'USERNAME': '', 'PASSWORD': ''}
                logtype = self.factory.canaryservice.logger.LOG_MSSQL_LOGIN_WINAUTH
                log = self.factory.canaryservice.log
                log(logdata, transport=self.transport, logtype=logtype)

            else:
               logtype = self.factory.canaryservice.logger.LOG_MSSQL_LOGIN_SQLAUTH
               log = self.factory.canaryservice.log
               log(loginData, transport=self.transport, logtype=logtype)
               username = loginData.get("UserName", "")
               errormsg = "Login failed for user %s." % username

            payload = self.buildError(errormsg, servername)
            # extra data observered on the wire
            payload += "\xfd\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

            rtds = TDSPacket(
                type=MSSQLProtocol.TDS_TYPE_RESPONSE,
                status=0x01,
                spid=54,
                packetid=0x01,
                window=0x00,
                payload=payload
            )

            self.transport.write(self.build_packet(rtds))

        elif tds.type == MSSQLProtocol.TDS_TYPE_SSPI:
            # FIXME: parse the SNEGO header correctly to extract the NTLM message
            i = tds.payload.find('NTLMSSP\x00')
            if i < 0:
                self.transport.abortConnection()
            ntlmtoken = tds.payload[i:]

            c = ChallengeResponse(0,0,0,'unspecified','unspecified')
            c.from_string(ntlmtoken)
            username = c['user_name'].decode('utf-16le')
            hostname = c['host_name'].decode('utf-16le')
            domain = c['domain_name'].decode('utf-16le')
            loginData = {
                'HOSTNAME' : hostname,
                'DOMAINNAME' : domain,
            }
            logtype = self.factory.logger.LOG_MSSQL_LOGIN_WINAUTH
            self.logAuth(username, None, loginData, logtype)

            payload = self.buildError("Login failed for user %s\\%s." % (domain,username) , hostname)
            # extra data observered on the wire
            payload += "\xfd\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

            rtds = TDSPacket(
                type=MSSQLProtocol.TDS_TYPE_RESPONSE,
                status=0x01,
                spid=54,
                packetid=0x01,
                window=0x00,
                payload=payload
            )

            self.transport.write(self.build_packet(rtds))

        elif tds.type == 128:
            # initial nmap probe: we're expected to reset connection
            self.transport.abortConnection()
        else:
            self.transport.abortConnection()

    def dataReceived(self, data):
        self._buffer += data
        self.resetTimeout()

        if self._busyReceiving:
            return

        try:
             self._busyReceiving = True
             tds = self.consume_packet()
             if tds is not None:
                 self.process(tds)
        finally:
             self._busyReceiving = False

    def timeoutConnection(self):
        self.transport.abortConnection()

class SQLFactory(Factory):
    def __init__(self):
        pass

    def buildProtocol(self, addr):
        return MSSQLProtocol(self)


class MSSQL(CanaryService):
    NAME = 'mssql'

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("mssql.port", default=1433))
        self.version = config.getVal("mssql.version", default="2012")
        self.listen_addr = config.getVal('device.listen_addr', default='')
        if self.version not in MSSQLProtocol.NMAP_PROBE_1_RESP:
            raise ConfigException("mssql.version", "Invalid MSSQL Version")

    def getService(self):
        factory = SQLFactory()
        factory.canaryservice = self
        return internet.TCPServer(self.port, factory, interface=self.listen_addr)
