from opencanary.modules import CanaryService
from opencanary.config import ConfigException

from twisted.protocols.policies import TimeoutMixin
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.application import internet
from random import randint

import struct
import re

UINT_MAX = 0xFFFFFFFF

class MySQL(Protocol, TimeoutMixin):
    HEADER_LEN              = 4
    ERR_CODE_ACCESS_DENIED  = 1045
    ERR_CODE_PKT_ORDER      = 1156
    SQL_STATE_ACCESS_DENIED = "2800"
    SQL_STATE_PKT_ORDER     = "08S01"

    # https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake
    def __init__(self, factory):
        self._busyReceiving = False
        self._buffer = ""
        self.factory = factory
        self.threadid = factory.next_threadid()
        self.setTimeout(10)

    @staticmethod
    def build_packet(seq_id, data):
        l = len(data)
        if l > 0xffffff or l <= 0:
            return None

        if seq_id > 0xff or seq_id < 0:
            return None

        # chop to 3 byte int
        _length = struct.pack('<I', l)[:-1]
        _seq_id = struct.pack('B', seq_id)

        return _length + _seq_id + data

    @staticmethod
    def parse_auth(data):
        # https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
        offset = 4 + 4 + 1 + 23
        i = data.find("\x00", offset)
        if i < 0:
            return None, None

        username = data[offset:i]
        i += 1
        plen = struct.unpack('B', data[i])[0]
        i+=1
        if plen == 0:
            return username, None

        password="".join("{:02x}".format(ord(c)) for c in data[i:i+plen])
        return username, password

    def consume_packet(self):
        if len(self._buffer) < MySQL.HEADER_LEN:
            return None, None

        length = struct.unpack('<I', self._buffer[:3] + '\x00')[0]
        seq_id = struct.unpack('<B', self._buffer[3])[0]

        # enough buffer data to consume packet?
        if len(self._buffer) < MySQL.HEADER_LEN + length:
            return seq_id, None

        payload = self._buffer[MySQL.HEADER_LEN: MySQL.HEADER_LEN + length]

        self._buffer = self._buffer[MySQL.HEADER_LEN + length:]

        return seq_id, payload

    def server_greeting(self):
        _threadid = struct.pack('<I', self.threadid)
        # TODO: randomize salts embedded here
        data = '\x0a' + self.factory.canaryservice.banner +'\x00' + _threadid + '\x25\x73\x36\x51\x74\x77\x75\x69\x00\xff\xf7\x08\x02\x00\x0f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2e\x47\x5c\x78\x67\x7a\x4f\x5b\x5c\x3e\x5c\x39\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00'
        return self.build_packet(0x00, data)

    def access_denied(self, seq_id, user, password=None):
        Y = "YES" if password else "NO"
        ip = self.transport.getPeer().host
        msg = "Access denied for user '%s'@'%s' (using password: %s)" % (user, ip, Y)
        return self.error_pkt(seq_id, MySQL.ERR_CODE_ACCESS_DENIED,
                              MySQL.SQL_STATE_ACCESS_DENIED, msg)

    def unordered_pkt(self, seq_id):
        msg = "Got packets out of order"
        return self.error_pkt(seq_id, MySQL.ERR_CODE_PKT_ORDER,
                              MySQL.SQL_STATE_PKT_ORDER, msg)

    def error_pkt(self, seq_id, err_code, sql_state, msg):
        data = "\xff" + struct.pack("<H", err_code) + "\x23#" + sql_state + msg
        return self.build_packet(0x02, data)

    def connectionMade(self):
        self.transport.write(self.server_greeting())

    def dataReceived(self, data):
        self._buffer += data
        self.resetTimeout()

        if self._busyReceiving:
            return

        try:
            self._busyReceiving = True
            seq_id, payload = self.consume_packet()
            if seq_id is None:
                return
            elif seq_id != 1:
                # error on wrong seq_id, even if payload hasn't arrived yet
                self.transport.write(self.unordered_pkt(0x01))
                self.transport.loseConnection()
                return
            elif payload is not None:
                # seq_id == 1 and payload has arrived
                username, password = self.parse_auth(payload)
                if username:
                    logdata = {'USERNAME': username, 'PASSWORD': password}
                    self.factory.canaryservice.log(logdata, transport=self.transport)
                    
                    self.transport.write(self.access_denied(0x02, username, password))
                    self.transport.loseConnection()
        finally:
            self._busyReceiving = False

    def timeoutConnection(self):
        self.transport.abortConnection()

class SQLFactory(Factory):
    def __init__(self):
        self.threadid = randint(0,0x0FFF)

    def next_threadid(self):
        self.threadid = (self.threadid + randint(1,5)) & UINT_MAX
        return self.threadid

    def buildProtocol(self, addr):
        return MySQL(self)


class CanaryMySQL(CanaryService):
    NAME = 'mysql'

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("mysql.port", default=3306))
        self.banner = config.getVal("mysql.banner", default="5.5.43-0ubuntu0.14.04.1").encode()
        self.logtype = logger.LOG_MYSQL_LOGIN_ATTEMPT
        self.listen_addr = config.getVal('device.listen_addr', default='')
        if re.search('^[3456]\.[-_~.+\w]+$', self.banner) is None:
            raise ConfigException("sql.banner", "Invalid MySQL Banner")


    def getService(self):
        factory = SQLFactory()
        factory.canaryservice = self
        return internet.TCPServer(self.port, factory, interface=self.listen_addr)
