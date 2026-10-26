from opencanary.modules import CanaryService

from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.application import internet
from twisted.internet import reactor
from twisted.protocols.policies import TimeoutMixin

from collections import namedtuple

import shlex

DEFAULT_MAX_ARG_LENGTH = 30
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_BULK_STRING_LENGTH = (
    2**20
)  # Maps to proto-max-bulk-len in redis.conf, set to 1mb
DEFAULT_MAX_CONNECTIONS = 128
MAX_UNAUTHED_BULK_STRING_LENGTH = (
    2**14
)  # 16 KB for unauthenticated clients, hardcoded in redis-server (processMultibulkBuffer())
MAX_ARRAY_ELEMENTS = 10  # Hardcoded in redis-server for unauthenticated clients
MAX_BUFFER_SIZE = (
    2**20
)  # 1 MB for unauthenticated clients, hardcoded in redis-server (readQueryFromClient())
MAX_COMMAND_BYTES = (
    64 * 1024
)  # Hardcoded for unauthenticated clients (PROTO_INLINE_MAX_SIZE)
MAX_ERROR_COMMAND_LENGTH = 128
ERROR_DRAIN_TIMEOUT = 1

ArgumentCount = namedtuple("ArgumentCount", "arg_min_count, arg_max_count")


def _sanitize_log_text(text):
    return text.replace("\r", " ").replace("\n", " ")


class ProtocolError(Exception):
    def __init__(self, reason, command=None, command_args=None):
        self.reason = _sanitize_log_text(reason)
        self.command = command
        self.command_args = command_args
        self.message = "-ERR Protocol error: {reason}\r\n".format(
            reason=self.reason
        ).encode("utf-8")


class ArgumentCountError(Exception):
    def __init__(self, cmd):
        cmd = _sanitize_log_text(
            cmd[:MAX_ERROR_COMMAND_LENGTH].decode("utf-8", errors="replace")
        )
        self.message = (
            "-ERR wrong number of arguments for '{cmd}' command\r\n".format(
                cmd=cmd.lower()
            )
        ).encode("utf-8")

        if cmd.upper() == "EXEC":
            self.message = (
                "-EXECABORT Transaction discarded because of: wrong number of arguments for '{cmd}' command\r\n".format(
                    cmd=cmd.lower()
                )
            ).encode("utf-8")


class AuthenticationRequiredError(Exception):
    def __init__(self, cmd):
        self.message = b"-NOAUTH Authentication required.\r\n"

        if cmd.upper() == "HELLO":
            self.message = b"-NOPROTO unsupported protocol version\r\n"

        if cmd.upper() == "EXEC":
            self.message = b"-EXECABORT Transaction discarded because of: NOAUTH Authentication required.\r\n"


class AuthenticationError(Exception):
    def __init__(self):
        self.message = b"-WRONGPASS invalid username-password pair\r\n"


class RedisSyntaxError(Exception):
    def __init__(self):
        self.message = b"-ERR syntax error\r\n"


class UnknownCommandError(Exception):
    def __init__(self, input_cmd, input_args):
        command = _sanitize_log_text(
            input_cmd[:MAX_ERROR_COMMAND_LENGTH].decode("utf-8", errors="replace")
        )

        args_error = ""
        for arg in input_args:
            remaining = MAX_ERROR_COMMAND_LENGTH - len(args_error.encode("utf-8"))
            if remaining <= 0:
                break

            arg = _sanitize_log_text(arg[:remaining].decode("utf-8", errors="replace"))
            args_error += "'{}' ".format(arg)

            if len(args_error.encode("utf-8")) >= MAX_ERROR_COMMAND_LENGTH:
                break

        self.message = (
            ("-ERR unknown command '{command}', with args beginning with: {args}\r\n")
            .format(command=command, args=args_error)
            .encode("utf-8")
        )


class RedisCommandAgain(Exception):
    pass


class RedisParser:
    pass


class RedisProtocol(Protocol, TimeoutMixin):
    """
    Implementation of basic RESP, that needs authentication.

    Responses for our protocol is based on v 6.0.20 of redis
    """

    COMMANDS = {
        b"ACL": ArgumentCount(1, None),
        b"ACL CAT": ArgumentCount(0, None),
        b"ACL DELUSER": ArgumentCount(0, None),
        b"ACL GENPASS": ArgumentCount(0, None),
        b"ACL GETUSER": ArgumentCount(0, None),
        b"ACL HELP": ArgumentCount(0, None),
        b"ACL LIST": ArgumentCount(0, None),
        b"ACL LOAD": ArgumentCount(0, None),
        b"ACL LOG": ArgumentCount(0, None),
        b"ACL SAVE": ArgumentCount(0, None),
        b"ACL SETUSER": ArgumentCount(0, None),
        b"ACL USERS": ArgumentCount(0, None),
        b"ACL WHOAMI": ArgumentCount(0, None),
        b"APPEND": ArgumentCount(2, 2),
        b"AUTH": ArgumentCount(1, None),
        b"ASKING": ArgumentCount(0, 0),
        b"BGREWRITEAOF": ArgumentCount(0, 0),
        b"BGSAVE": ArgumentCount(0, None),
        b"BITCOUNT": ArgumentCount(1, None),
        b"BITFIELD": ArgumentCount(1, None),
        b"BITFIELD_RO": ArgumentCount(1, None),
        b"BITOP": ArgumentCount(3, None),
        b"BITPOS": ArgumentCount(2, None),
        b"BLPOP": ArgumentCount(2, None),
        b"BRPOP": ArgumentCount(2, None),
        b"BRPOPLPUSH": ArgumentCount(3, 3),
        b"BZPOPMAX": ArgumentCount(2, None),
        b"BZPOPMIN": ArgumentCount(2, None),
        b"CLIENT": ArgumentCount(1, None),
        b"CLIENT CACHING": ArgumentCount(0, None),
        b"CLIENT GETNAME": ArgumentCount(0, None),
        b"CLIENT GETREDIR": ArgumentCount(0, None),
        b"CLIENT HELP": ArgumentCount(0, None),
        b"CLIENT ID": ArgumentCount(0, None),
        b"CLIENT KILL": ArgumentCount(0, None),
        b"CLIENT LIST": ArgumentCount(0, None),
        b"CLIENT PAUSE": ArgumentCount(0, None),
        b"CLIENT REPLY": ArgumentCount(0, None),
        b"CLIENT SETNAME": ArgumentCount(0, None),
        b"CLIENT TRACKING": ArgumentCount(0, None),
        b"CLIENT UNBLOCK": ArgumentCount(0, None),
        b"CLUSTER": ArgumentCount(1, None),
        b"CLUSTER ADDSLOTS": ArgumentCount(0, None),
        b"CLUSTER BUMPEPOCH": ArgumentCount(0, None),
        b"CLUSTER COUNT-FAILURE-REPORTS": ArgumentCount(0, None),
        b"CLUSTER COUNTKEYSINSLOT": ArgumentCount(0, None),
        b"CLUSTER DELSLOTS": ArgumentCount(0, None),
        b"CLUSTER FAILOVER": ArgumentCount(0, None),
        b"CLUSTER FLUSHSLOTS": ArgumentCount(0, None),
        b"CLUSTER FORGET": ArgumentCount(0, None),
        b"CLUSTER GETKEYSINSLOT": ArgumentCount(0, None),
        b"CLUSTER HELP": ArgumentCount(0, None),
        b"CLUSTER INFO": ArgumentCount(0, None),
        b"CLUSTER KEYSLOT": ArgumentCount(0, None),
        b"CLUSTER MEET": ArgumentCount(0, None),
        b"CLUSTER MYID": ArgumentCount(0, None),
        b"CLUSTER NODES": ArgumentCount(0, None),
        b"CLUSTER REPLICAS": ArgumentCount(0, None),
        b"CLUSTER REPLICATE": ArgumentCount(0, None),
        b"CLUSTER RESET": ArgumentCount(0, None),
        b"CLUSTER SAVECONFIG": ArgumentCount(0, None),
        b"CLUSTER SET-CONFIG-EPOCH": ArgumentCount(0, None),
        b"CLUSTER SETSLOT": ArgumentCount(0, None),
        b"CLUSTER SLAVES": ArgumentCount(0, None),
        b"CLUSTER SLOTS": ArgumentCount(0, None),
        b"COMMAND": ArgumentCount(0, None),
        b"COMMAND COUNT": ArgumentCount(0, None),
        b"COMMAND GETKEYS": ArgumentCount(0, None),
        b"COMMAND HELP": ArgumentCount(0, None),
        b"COMMAND INFO": ArgumentCount(0, None),
        b"CONFIG": ArgumentCount(1, None),
        b"CONFIG GET": ArgumentCount(0, None),
        b"CONFIG HELP": ArgumentCount(0, None),
        b"CONFIG RESETSTAT": ArgumentCount(0, None),
        b"CONFIG REWRITE": ArgumentCount(0, None),
        b"CONFIG SET": ArgumentCount(0, None),
        b"DBSIZE": ArgumentCount(0, 0),
        b"DEBUG": ArgumentCount(1, None),
        b"DECR": ArgumentCount(1, 1),
        b"DECRBY": ArgumentCount(2, 2),
        b"DEL": ArgumentCount(1, None),
        b"DISCARD": ArgumentCount(0, 0),
        b"DUMP": ArgumentCount(1, 1),
        b"ECHO": ArgumentCount(1, 1),
        b"EVAL": ArgumentCount(2, None),
        b"EVALSHA": ArgumentCount(2, None),
        b"EXEC": ArgumentCount(0, 0),
        b"EXISTS": ArgumentCount(1, None),
        b"EXPIRE": ArgumentCount(2, 2),
        b"EXPIREAT": ArgumentCount(2, 2),
        b"FLUSHALL": ArgumentCount(0, None),
        b"FLUSHDB": ArgumentCount(0, None),
        b"GEOADD": ArgumentCount(4, None),
        b"GEODIST": ArgumentCount(3, None),
        b"GEOHASH": ArgumentCount(1, None),
        b"GEOPOS": ArgumentCount(1, None),
        b"GEORADIUS_RO": ArgumentCount(5, None),
        b"GEORADIUS": ArgumentCount(5, None),
        b"GEORADIUSBYMEMBER_RO": ArgumentCount(4, None),
        b"GEORADIUSBYMEMBER": ArgumentCount(4, None),
        b"GET": ArgumentCount(1, 1),
        b"GETBIT": ArgumentCount(2, 2),
        b"GETRANGE": ArgumentCount(3, 3),
        b"GETSET": ArgumentCount(2, 2),
        b"HELLO": ArgumentCount(1, None),
        b"HDEL": ArgumentCount(2, None),
        b"HEXISTS": ArgumentCount(2, 2),
        b"HGET": ArgumentCount(2, 2),
        b"HGETALL": ArgumentCount(1, 1),
        b"HINCRBY": ArgumentCount(3, 3),
        b"HINCRBYFLOAT": ArgumentCount(3, 3),
        b"HKEYS": ArgumentCount(1, 1),
        b"HLEN": ArgumentCount(1, 1),
        b"HMGET": ArgumentCount(2, None),
        b"HMSET": ArgumentCount(3, None),
        b"HSCAN": ArgumentCount(2, None),
        b"HSET": ArgumentCount(3, None),
        b"HSETNX": ArgumentCount(3, 3),
        b"HSTRLEN": ArgumentCount(2, 2),
        b"HVALS": ArgumentCount(1, 1),
        b"INCR": ArgumentCount(1, 1),
        b"INCRBY": ArgumentCount(2, 2),
        b"INCRBYFLOAT": ArgumentCount(2, 2),
        b"INFO": ArgumentCount(0, None),
        b"KEYS": ArgumentCount(1, 1),
        b"LASTSAVE": ArgumentCount(0, 0),
        b"LATENCY": ArgumentCount(1, None),
        b"LATENCY DOCTOR": ArgumentCount(0, None),
        b"LATENCY GRAPH": ArgumentCount(0, None),
        b"LATENCY HELP": ArgumentCount(0, None),
        b"LATENCY HISTORY": ArgumentCount(0, None),
        b"LATENCY LATEST": ArgumentCount(0, None),
        b"LATENCY RESET": ArgumentCount(0, None),
        b"LINDEX": ArgumentCount(2, 2),
        b"LINSERT": ArgumentCount(4, 4),
        b"LLEN": ArgumentCount(1, 1),
        b"LOLWUT": ArgumentCount(0, None),
        b"LPOP": ArgumentCount(1, 1),
        b"LPOS": ArgumentCount(2, None),
        b"LPUSH": ArgumentCount(2, None),
        b"LPUSHX": ArgumentCount(2, None),
        b"LRANGE": ArgumentCount(3, 3),
        b"LREM": ArgumentCount(3, 3),
        b"LSET": ArgumentCount(3, 3),
        b"LTRIM": ArgumentCount(3, 3),
        b"MEMORY": ArgumentCount(1, None),
        b"MEMORY DOCTOR": ArgumentCount(0, None),
        b"MEMORY HELP": ArgumentCount(0, None),
        b"MEMORY MALLOC-STATS": ArgumentCount(0, None),
        b"MEMORY PURGE": ArgumentCount(0, None),
        b"MEMORY STATS": ArgumentCount(0, None),
        b"MEMORY USAGE": ArgumentCount(0, None),
        b"MGET": ArgumentCount(1, None),
        b"MIGRATE": ArgumentCount(5, None),
        b"MODULE": ArgumentCount(1, None),
        b"MODULE HELP": ArgumentCount(0, None),
        b"MODULE LIST": ArgumentCount(0, None),
        b"MODULE LOAD": ArgumentCount(0, None),
        b"MODULE UNLOAD": ArgumentCount(0, None),
        b"MONITOR": ArgumentCount(0, 0),
        b"MOVE": ArgumentCount(2, 2),
        b"MSET": ArgumentCount(2, None),
        b"MSETNX": ArgumentCount(2, None),
        b"MULTI": ArgumentCount(0, 0),
        b"OBJECT": ArgumentCount(1, None),
        b"OBJECT ENCODING": ArgumentCount(0, None),
        b"OBJECT FREQ": ArgumentCount(0, None),
        b"OBJECT IDLETIME": ArgumentCount(0, None),
        b"OBJECT REFCOUNT": ArgumentCount(0, None),
        b"PERSIST": ArgumentCount(1, 1),
        b"PEXPIRE": ArgumentCount(2, 2),
        b"PEXPIREAT": ArgumentCount(2, 2),
        b"PFADD": ArgumentCount(1, None),
        b"PFCOUNT": ArgumentCount(1, None),
        b"PFDEBUG": ArgumentCount(2, None),
        b"PFMERGE": ArgumentCount(1, None),
        b"PFSELFTEST": ArgumentCount(0, 0),
        b"PING": ArgumentCount(0, None),
        b"PSETEX": ArgumentCount(3, 3),
        b"PSUBSCRIBE": ArgumentCount(1, None),
        b"PSYNC": ArgumentCount(2, 2),
        b"PTTL": ArgumentCount(1, 1),
        b"PUBLISH": ArgumentCount(2, 2),
        b"PUBSUB": ArgumentCount(1, None),
        b"PUBSUB CHANNELS": ArgumentCount(0, None),
        b"PUBSUB NUMPAT": ArgumentCount(0, None),
        b"PUBSUB NUMSUB": ArgumentCount(0, None),
        b"PUNSUBSCRIBE": ArgumentCount(0, None),
        b"QUIT": ArgumentCount(0, None),
        b"RANDOMKEY": ArgumentCount(0, 0),
        b"READONLY": ArgumentCount(0, 0),
        b"READWRITE": ArgumentCount(0, 0),
        b"RENAME": ArgumentCount(2, 2),
        b"RENAMENX": ArgumentCount(2, 2),
        b"REPLCONF": ArgumentCount(0, None),
        b"REPLICAOF": ArgumentCount(2, 2),
        b"RESTORE-ASKING": ArgumentCount(3, None),
        b"RESTORE": ArgumentCount(3, None),
        b"ROLE": ArgumentCount(0, 0),
        b"RPOP": ArgumentCount(1, 1),
        b"RPOPLPUSH": ArgumentCount(2, 2),
        b"RPUSH": ArgumentCount(2, None),
        b"RPUSHX": ArgumentCount(2, None),
        b"SADD": ArgumentCount(2, None),
        b"SAVE": ArgumentCount(0, 0),
        b"SCAN": ArgumentCount(1, None),
        b"SCARD": ArgumentCount(1, 1),
        b"SCRIPT": ArgumentCount(1, None),
        b"SCRIPT DEBUG": ArgumentCount(0, None),
        b"SCRIPT EXISTS": ArgumentCount(0, None),
        b"SCRIPT FLUSH": ArgumentCount(0, None),
        b"SCRIPT HELP": ArgumentCount(0, None),
        b"SCRIPT KILL": ArgumentCount(0, None),
        b"SCRIPT LOAD": ArgumentCount(0, None),
        b"SDIFF": ArgumentCount(1, None),
        b"SDIFFSTORE": ArgumentCount(2, None),
        b"SELECT": ArgumentCount(1, 1),
        b"SET": ArgumentCount(2, None),
        b"SETBIT": ArgumentCount(3, 3),
        b"SETEX": ArgumentCount(3, 3),
        b"SETNX": ArgumentCount(2, 2),
        b"SETRANGE": ArgumentCount(3, 3),
        b"SHUTDOWN": ArgumentCount(0, None),
        b"SINTER": ArgumentCount(1, None),
        b"SINTERSTORE": ArgumentCount(2, None),
        b"SISMEMBER": ArgumentCount(2, 2),
        b"SLAVEOF": ArgumentCount(2, 2),
        b"SLOWLOG": ArgumentCount(1, None),
        b"SLOWLOG GET": ArgumentCount(0, None),
        b"SLOWLOG LEN": ArgumentCount(0, None),
        b"SLOWLOG RESET": ArgumentCount(0, None),
        b"SMEMBERS": ArgumentCount(1, 1),
        b"SMOVE": ArgumentCount(3, 3),
        b"SORT": ArgumentCount(1, None),
        b"SPOP": ArgumentCount(1, None),
        b"SRANDMEMBER": ArgumentCount(1, None),
        b"SREM": ArgumentCount(2, None),
        b"SSCAN": ArgumentCount(2, None),
        b"STRLEN": ArgumentCount(1, 1),
        b"SUBSCRIBE": ArgumentCount(1, None),
        b"SUBSTR": ArgumentCount(3, 3),
        b"SUNION": ArgumentCount(1, None),
        b"SUNIONSTORE": ArgumentCount(2, None),
        b"SWAPDB": ArgumentCount(2, 2),
        b"SYNC": ArgumentCount(0, 0),
        b"TIME": ArgumentCount(0, 0),
        b"TOUCH": ArgumentCount(1, None),
        b"TTL": ArgumentCount(1, 1),
        b"TYPE": ArgumentCount(1, 1),
        b"UNLINK": ArgumentCount(1, None),
        b"UNSUBSCRIBE": ArgumentCount(0, None),
        b"UNWATCH": ArgumentCount(0, 0),
        b"WAIT": ArgumentCount(2, 2),
        b"WATCH": ArgumentCount(1, None),
        b"XACK": ArgumentCount(3, None),
        b"XADD": ArgumentCount(4, None),
        b"XCLAIM": ArgumentCount(5, None),
        b"XDEL": ArgumentCount(2, None),
        b"XGROUP": ArgumentCount(1, None),
        b"XGROUP CREATE": ArgumentCount(0, None),
        b"XGROUP DELCONSUMER": ArgumentCount(0, None),
        b"XGROUP DESTROY": ArgumentCount(0, None),
        b"XGROUP HELP": ArgumentCount(0, None),
        b"XGROUP SETID": ArgumentCount(0, None),
        b"XINFO": ArgumentCount(1, None),
        b"XINFO CONSUMERS": ArgumentCount(0, None),
        b"XINFO GROUPS": ArgumentCount(0, None),
        b"XINFO HELP": ArgumentCount(0, None),
        b"XINFO STREAM": ArgumentCount(0, None),
        b"XLEN": ArgumentCount(1, 1),
        b"XPENDING": ArgumentCount(2, None),
        b"XRANGE": ArgumentCount(3, None),
        b"XREAD": ArgumentCount(3, None),
        b"XREADGROUP": ArgumentCount(6, None),
        b"XREVRANGE": ArgumentCount(3, None),
        b"XSETID": ArgumentCount(2, 2),
        b"XTRIM": ArgumentCount(1, None),
        b"ZADD": ArgumentCount(3, None),
        b"ZCARD": ArgumentCount(1, 1),
        b"ZCOUNT": ArgumentCount(3, 3),
        b"ZINCRBY": ArgumentCount(3, 3),
        b"ZINTERSTORE": ArgumentCount(3, None),
        b"ZLEXCOUNT": ArgumentCount(3, 3),
        b"ZPOPMAX": ArgumentCount(1, None),
        b"ZPOPMIN": ArgumentCount(1, None),
        b"ZRANGE": ArgumentCount(3, None),
        b"ZRANGEBYLEX": ArgumentCount(3, None),
        b"ZRANGEBYSCORE": ArgumentCount(3, None),
        b"ZRANK": ArgumentCount(2, 2),
        b"ZREM": ArgumentCount(2, None),
        b"ZREMRANGEBYLEX": ArgumentCount(3, 3),
        b"ZREMRANGEBYRANK": ArgumentCount(3, 3),
        b"ZREMRANGEBYSCORE": ArgumentCount(3, 3),
        b"ZREVRANGE": ArgumentCount(3, None),
        b"ZREVRANGEBYLEX": ArgumentCount(3, None),
        b"ZREVRANGEBYSCORE": ArgumentCount(3, None),
        b"ZREVRANK": ArgumentCount(2, 2),
        b"ZSCAN": ArgumentCount(2, None),
        b"ZSCORE": ArgumentCount(2, 2),
        b"ZUNIONSTORE": ArgumentCount(3, None),
    }

    def connectionMade(self):
        self._data = b""
        self._counted_connection = False
        self._discarding_after_error = False
        self._error_close_call = None

        max_connections = self.factory.max_connections
        if max_connections is not None and max_connections > 0:
            active_connections = self.factory.active_connections
            if active_connections >= max_connections:
                self._logProtocolError("max connections exceeded")
                self.transport.loseConnection()
                return

            self.factory.active_connections = active_connections + 1
            self._counted_connection = True

        timeout = self.factory.timeout
        if timeout == 0:
            timeout = None
        self.setTimeout(timeout)

    def connectionLost(self, reason):
        if self._error_close_call is not None and self._error_close_call.active():
            self._error_close_call.cancel()
        self._error_close_call = None

        self.setTimeout(None)

        if self._counted_connection:
            self.factory.active_connections = max(
                0, self.factory.active_connections - 1
            )
            self._counted_connection = False

    def _abortErrorConnection(self):
        self._error_close_call = None
        self.transport.abortConnection()

    def callLater(self, period, func):
        return self.factory.reactor.callLater(period, func)

    def timeoutConnection(self):
        if not self._data:
            self.transport.loseConnection()
            return

        self._errorAndClose(
            b""
        )  # Nothing is sent on timeout, the connection is simply closed

    def _parseLength(self, value, error_reason, max_length):
        if not value or not value.isdigit():
            raise ProtocolError(error_reason)

        if len(value) > len(str(max_length)):
            raise ProtocolError(error_reason)

        if value != "0" and value.startswith(b"0"):
            raise ProtocolError(error_reason)

        try:
            length = int(value)
        except (TypeError, ValueError, OverflowError):
            raise ProtocolError(error_reason)

        if length <= max_length:
            return length

        raise ProtocolError(error_reason)

    def _parseStringLength(self, value):
        max_bulk_string_length = self.factory.max_bulk_string_length

        str_len = self._parseLength(
            value, "invalid bulk length", max_bulk_string_length
        )

        if (
            str_len > MAX_UNAUTHED_BULK_STRING_LENGTH
            and str_len <= max_bulk_string_length
        ):
            raise ProtocolError("unauthenticated bulk length")

        if str_len < 0:
            raise ProtocolError("invalid bulk length")

        return str_len

    def _parseArrayLength(self, value, error_reason):
        return self._parseLength(value, error_reason, MAX_ARRAY_ELEMENTS)

    def _parseInlineCommand(self, data):
        line_end = data.find(b"\n")
        if line_end == -1:
            if len(data) > MAX_COMMAND_BYTES:
                raise ProtocolError("too big inline request")
            raise RedisCommandAgain()

        command_bytes = line_end + 1
        if command_bytes > MAX_COMMAND_BYTES:
            raise ProtocolError("too big inline request")

        line = data[:line_end]
        if line.endswith(b"\r"):
            line = line[:-1]

        try:
            tokens = [
                t.encode("utf-8")
                for t in shlex.split(line.decode("utf-8", errors="replace"))
            ]
        except ValueError:
            raise ProtocolError("unbalanced quotes in request")

        if not tokens:
            raise ProtocolError("empty command")

        cmd, args = self._extract_command(tokens)
        return cmd, args, data[line_end + 1 :]

    def _parseRESPCommandArguments(self, data, curr_ptr):
        command = None
        command_args = None
        elements = []

        # We capture a bounded amount of elements so we can see the
        # command and its arguments in the alert up to a maximum of MAX_ARRAY_ELEMENTS + 1.
        for _ in range(MAX_ARRAY_ELEMENTS + 1):
            try:
                element, curr_ptr = self._parseRESPString(data, curr_ptr)
            except (ProtocolError, RedisCommandAgain):
                break
            elements.append(element)

        if elements:
            command, command_args = self._extract_command(elements)

        return command, command_args

    def _parseRESPArray(self, data):
        """
        RESP arrays with strings look like:
            *<element_count>\r\n
            $<string_1_length>\r\n
            <string_1>\r\n
            $<string_2_length>\r\n
            <string_2>\r\n
        """
        if data[:1] != b"*":
            marker = _sanitize_log_text(data[:1].decode("utf-8", errors="replace"))
            raise ProtocolError("expected '*', got '{c}'".format(c=marker))

        curr_ptr = data.find(b"\r\n")
        if curr_ptr == -1:
            if len(data) > MAX_COMMAND_BYTES:
                raise ProtocolError("too big mbulk count string")
            raise RedisCommandAgain()

        arr_count = self._parseLength(
            data[1:curr_ptr], "invalid multibulk length", 2**31 - 1
        )  # Valid sizes < 2GB
        if arr_count < 1:
            raise ProtocolError("invalid multibulk length")

        curr_ptr += 2
        if arr_count > MAX_ARRAY_ELEMENTS:
            command, command_args = self._parseRESPCommandArguments(data, curr_ptr)
            raise ProtocolError(
                "unauthenticated multibulk length",
                command=command,
                command_args=command_args,
            )

        array = []
        for _ in range(arr_count):
            elem_str, curr_ptr = self._parseRESPString(data, curr_ptr)
            if curr_ptr > MAX_COMMAND_BYTES:
                raise ProtocolError("invalid bulk length")
            array.append(elem_str)

        return array, curr_ptr

    def _parseRESPString(self, data, curr_ptr):
        if curr_ptr >= len(data):
            raise RedisCommandAgain()

        if data[curr_ptr : curr_ptr + 1] != b"$":
            marker = _sanitize_log_text(
                data[curr_ptr : curr_ptr + 1].decode("utf-8", errors="replace")
            )
            raise ProtocolError("expected '$', got '{c}'".format(c=marker))

        line_end = data.find(b"\r\n", curr_ptr)
        if line_end == -1:
            if len(data) > MAX_COMMAND_BYTES:
                raise ProtocolError("too big bulk count string")
            raise RedisCommandAgain()

        str_length = self._parseStringLength(data[curr_ptr + 1 : line_end])
        if str_length < 0:
            raise ProtocolError("invalid bulk length")

        body_start = line_end + 2
        body_end = body_start + str_length
        frame_end = body_end + 2
        if frame_end > MAX_COMMAND_BYTES:
            raise ProtocolError("invalid bulk length")
        if len(data) < frame_end:
            raise RedisCommandAgain()
        if data[body_end:frame_end] != b"\r\n":
            raise ProtocolError("invalid bulk length")

        return data[body_start:body_end], frame_end

    def _parseRESPCommand(self, data):
        array, curr_ptr = self._parseRESPArray(data)
        cmd, args = self._extract_command(array)
        return cmd, args, data[curr_ptr:]

    def _buildResponseAndSend(self, input_cmd, input_args):
        try:
            input_cmd_upper = input_cmd.upper()

            if input_cmd_upper not in self.COMMANDS:
                raise UnknownCommandError(input_cmd, input_args)

            arg_min_count = self.COMMANDS[input_cmd_upper].arg_min_count
            arg_max_count = self.COMMANDS[input_cmd_upper].arg_max_count
            input_arg_count = len(input_args)

            if any(
                (
                    input_arg_count < arg_min_count,
                    arg_max_count is not None and input_arg_count > arg_max_count,
                )
            ):
                raise ArgumentCountError(input_cmd)

            if input_cmd_upper == "QUIT":
                self.transport.write(b"+OK\r\n")
                self.transport.loseConnection()
                return

            if input_cmd_upper == "AUTH":
                if input_arg_count > 2:  # special case of max count for auth
                    raise RedisSyntaxError()
                raise AuthenticationError()

            raise AuthenticationRequiredError(input_cmd_upper)

        except (
            UnknownCommandError,
            ArgumentCountError,
            AuthenticationError,
            AuthenticationRequiredError,
            RedisSyntaxError,
            ProtocolError,
        ) as e:
            self._logAlert(input_cmd, input_args)
            self.transport.write(e.message)
        return

    def _logAlert(self, cmd, args):
        max_arg_length = self.factory.max_arg_length
        args = b" ".join(args)
        if max_arg_length is not None:
            cmd = cmd[:max_arg_length]
            args = args[:max_arg_length]
        logdata = {
            "CMD": _sanitize_log_text(cmd.decode("utf-8", errors="replace")),
            "ARGS": _sanitize_log_text(args.decode("utf-8", errors="replace")),
        }
        self.factory.log(logdata, transport=self.transport)

    def _extract_command(self, data):
        # Check if we have a command and subcommand
        subcommand = b" ".join(data[:2])

        if subcommand.upper() in self.COMMANDS:
            return subcommand, data[2:]

        return data[0], data[1:]

    def _logProtocolError(self, reason, command=None, command_args=None):
        command_args = command_args or []
        max_arg_length = self.factory.max_arg_length
        args = b" ".join(command_args)
        if max_arg_length is not None:
            args = args[:max_arg_length]

        logdata = {
            "CMD": (
                _sanitize_log_text(
                    command[:max_arg_length].decode("utf-8", errors="replace")
                    if max_arg_length is not None
                    else command.decode("utf-8", errors="replace")
                )
                if command is not None
                else ""
            ),
            "ARGS": _sanitize_log_text(args.decode("utf-8", errors="replace")),
            "ERROR": _sanitize_log_text(reason),
        }
        self.factory.log(logdata, transport=self.transport)

    def _processRedisCommand(self):
        commands = []
        while len(self._data) > 0:
            original_data = self._data
            try:
                if self._data.startswith(b"*"):
                    cmd, args, self._data = self._parseRESPCommand(self._data)
                else:
                    cmd, args, self._data = self._parseInlineCommand(self._data)
            except RedisCommandAgain:
                self._data = original_data
                return commands, True

            commands.append((cmd, args))

        return commands, False

    def dataReceived(self, data):
        """
        Received data is unbuffered so we buffer it until a Redis command completes.
        """
        if self._discarding_after_error:
            return

        try:
            if len(data) > 0:
                self.resetTimeout()

            if len(self._data) + len(data) > MAX_BUFFER_SIZE:
                self._logProtocolError(
                    "request buffer too large: {}".format(len(self._data) + len(data))
                )
                self._errorAndClose(ProtocolError("invalid").message)
                return

            self._data += data
            cmds, incomplete = self._processRedisCommand()

            for cmd, args in cmds:
                self._buildResponseAndSend(cmd, args)

        except (ProtocolError, IndexError, UnicodeDecodeError) as e:
            if not isinstance(e, ProtocolError):
                e = ProtocolError("malformed request")
            self._logProtocolError(e.reason, e.command, e.command_args)
            self._errorAndClose(e.message)
            return

    def _errorAndClose(self, error_msg):
        if self._discarding_after_error:
            return

        self._data = b""
        self._discarding_after_error = True
        self.transport.write(error_msg)
        self.transport.loseWriteConnection()
        self._error_close_call = self.factory.reactor.callLater(
            ERROR_DRAIN_TIMEOUT, self._abortErrorConnection
        )


class CanaryRedis(Factory, CanaryService):
    NAME = "redis"
    protocol = RedisProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.port = config.getVal("redis.port", default=6379)
        self.max_arg_length = int(
            config.getVal("redis.max_arg_length", default=DEFAULT_MAX_ARG_LENGTH)
        )
        self.max_bulk_string_length = int(
            config.getVal(
                "redis.max_bulk_string_length", default=DEFAULT_MAX_BULK_STRING_LENGTH
            )
        )
        self.timeout = float(config.getVal("redis.timeout", default=DEFAULT_TIMEOUT))
        self.max_connections = int(
            config.getVal("redis.max_connections", default=DEFAULT_MAX_CONNECTIONS)
        )
        self.active_connections = 0
        self.reactor = reactor
        self.logtype = logger.LOG_REDIS_COMMAND

    def getService(self):
        return internet.TCPServer(self.port, self, interface=self.listen_addr)
