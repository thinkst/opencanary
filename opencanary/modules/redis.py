from opencanary.modules import CanaryService

from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.application import internet

import shlex


class ProtocolError(Exception):
    def __init__(self, reason):
        self.message = b"-ERR Protocol error: {reason}\r\n".format(reason=reason)


class ArgumentCountError(Exception):
    def __init__(self, cmd):
        self.message = b"-ERR wrong number of arguments for '{cmd}' command\r\n".format(
            cmd=cmd.lower()
        )


class AuthenticationRequiredError(Exception):
    def __init__(self):
        self.message = b"-NOAUTH Authentication required.\r\n"


class AuthenticationError(Exception):
    def __init__(self):
        self.message = b"-ERR invalid password\r\n"


class UnknownCommandError(Exception):
    def __init__(self, cmd):
        cmd.replace("\r", " ").replace("\n", " ")
        self.message = (
            "-ERR unknown command '{cmd}'\r\n".format(cmd=cmd.lower())
        ).encode("utf-8")


class RedisCommandAgain(Exception):
    pass


class RedisParser:
    pass


class RedisProtocol(Protocol):
    """
    Implementation of basic RESP, that needs authentication.
    """

    COMMANDS = {
        "APPEND": (2, 2),
        "AUTH": (1, 1),
        "BGREWRITEAOF": (0, 0),
        "BGSAVE": (0, None),
        "BITCOUNT": (1, None),
        "BITFIELD": (1, None),
        "BITOP": (3, None),
        "BITPOS": (2, None),
        "BLPOP": (2, None),
        "BRPOP": (2, None),
        "BRPOPLPUSH": (3, 3),
        "CLIENT GETNAME": (0, None),
        "CLIENT KILL": (0, None),
        "CLIENT LIST": (0, None),
        "CLIENT PAUSE": (0, None),
        "CLIENT REPLY": (0, None),
        "CLIENT SETNAME": (0, None),
        "CLUSTER ADDSLOTS": (0, None),
        "CLUSTER COUNT-FAILURE-REPORTS": (0, None),
        "CLUSTER COUNTKEYSINSLOT": (0, None),
        "CLUSTER DELSLOTS": (0, None),
        "CLUSTER FAILOVER": (0, None),
        "CLUSTER FORGET": (0, None),
        "CLUSTER GETKEYSINSLOT": (0, None),
        "CLUSTER INFO": (0, None),
        "CLUSTER KEYSLOT": (0, None),
        "CLUSTER MEET": (0, None),
        "CLUSTER NODES": (0, None),
        "CLUSTER REPLICATE": (0, None),
        "CLUSTER RESET": (0, None),
        "CLUSTER SAVECONFIG": (0, None),
        "CLUSTER SET-CONFIG-EPOCH": (0, None),
        "CLUSTER SETSLOT": (0, None),
        "CLUSTER SLAVES": (0, None),
        "CLUSTER SLOTS": (0, None),
        "COMMAND COUNT": (0, None),
        "COMMAND GETKEYS": (0, None),
        "COMMAND INFO": (0, None),
        "COMMAND": (0, None),
        "CONFIG GET": (0, None),
        "CONFIG RESETSTAT": (0, None),
        "CONFIG REWRITE": (0, None),
        "CONFIG SET": (0, None),
        "DBSIZE": (0, 0),
        "DEBUG OBJECT": (0, None),
        "DEBUG SEGFAULT": (0, None),
        "DECR": (1, 1),
        "DECRBY": (2, 2),
        "DEL": (1, None),
        "DISCARD": (0, 0),
        "DUMP": (1, 1),
        "ECHO": (1, 1),
        "EVAL": (2, None),
        "EVALSHA": (2, None),
        "EXEC": (0, 0),
        "EXISTS": (1, None),
        "EXPIRE": (2, 2),
        "EXPIREAT": (2, 2),
        "FLUSHALL": (0, 0),
        "FLUSHDB": (0, 0),
        "GEOADD": (4, None),
        "GEODIST": (3, None),
        "GEOHASH": (1, None),
        "GEOPOS": (1, None),
        "GEORADIUS": (5, None),
        "GEORADIUSBYMEMBER": (4, None),
        "GET": (1, 1),
        "GETBIT": (2, 2),
        "GETRANGE": (3, 3),
        "GETSET": (2, 2),
        "HDEL": (2, None),
        "HEXISTS": (2, 2),
        "HGET": (2, 2),
        "HGETALL": (1, 1),
        "HINCRBY": (3, 3),
        "HINCRBYFLOAT": (3, 3),
        "HKEYS": (1, 1),
        "HLEN": (1, 1),
        "HMGET": (2, None),
        "HMSET": (3, None),
        "HSCAN": (2, None),
        "HSET": (3, 3),
        "HSETNX": (3, 3),
        "HSTRLEN": (2, 2),
        "HVALS": (1, 1),
        "INCR": (1, 1),
        "INCRBY": (2, 2),
        "INCRBYFLOAT": (2, 2),
        "INFO": (0, None),
        "KEYS": (1, 1),
        "LASTSAVE": (0, 0),
        "LINDEX": (2, 2),
        "LINSERT": (4, 4),
        "LLEN": (1, 1),
        "LPOP": (1, 1),
        "LPUSH": (2, None),
        "LPUSHX": (2, 2),
        "LRANGE": (3, 3),
        "LREM": (3, 3),
        "LSET": (3, 3),
        "LTRIM": (3, 3),
        "MGET": (1, None),
        "MIGRATE": (5, None),
        "MONITOR": (0, 0),
        "MOVE": (2, 2),
        "MSET": (2, None),
        "MSETNX": (2, None),
        "MULTI": (0, 0),
        "OBJECT": (2, 2),
        "PERSIST": (1, 1),
        "PEXPIRE": (2, 2),
        "PEXPIREAT": (2, 2),
        "PFADD": (1, None),
        "PFCOUNT": (1, None),
        "PFMERGE": (1, None),
        "PING": (0, None),
        "PSETEX": (3, 3),
        "PSUBSCRIBE": (1, None),
        "PTTL": (1, 1),
        "PUBLISH": (2, 2),
        "PUBSUB": (1, None),
        "PUNSUBSCRIBE": (0, None),
        "QUIT": (0, None),
        "RANDOMKEY": (0, 0),
        "READONLY": (0, 0),
        "READWRITE": (0, 0),
        "RENAME": (2, 2),
        "RENAMENX": (2, 2),
        "RESTORE": (3, None),
        "ROLE": (0, 0),
        "RPOP": (1, 1),
        "RPOPLPUSH": (2, 2),
        "RPUSH": (2, None),
        "RPUSHX": (2, 2),
        "SADD": (2, None),
        "SAVE": (0, 0),
        "SCAN": (1, None),
        "SCARD": (1, 1),
        "SCRIPT DEBUG": (0, None),
        "SCRIPT EXISTS": (0, None),
        "SCRIPT FLUSH": (0, None),
        "SCRIPT KILL": (0, None),
        "SCRIPT LOAD": (0, None),
        "SDIFF": (1, None),
        "SDIFFSTORE": (2, None),
        "SELECT": (1, 1),
        "SET": (2, None),
        "SETBIT": (3, 3),
        "SETEX": (3, 3),
        "SETNX": (2, 2),
        "SETRANGE": (3, 3),
        "SHUTDOWN": (0, None),
        "SINTER": (1, None),
        "SINTERSTORE": (2, None),
        "SISMEMBER": (2, 2),
        "SLAVEOF": (2, 2),
        "SLOWLOG": (1, None),
        "SMEMBERS": (1, 1),
        "SMOVE": (3, 3),
        "SORT": (1, None),
        "SPOP": (1, None),
        "SRANDMEMBER": (1, None),
        "SREM": (2, None),
        "SSCAN": (2, None),
        "STRLEN": (1, 1),
        "SUBSCRIBE": (1, None),
        "SUNION": (1, None),
        "SUNIONSTORE": (2, None),
        "SYNC": (0, 0),
        "TIME": (0, 0),
        "TOUCH": (1, None),
        "TTL": (1, 1),
        "TYPE": (1, 1),
        "UNSUBSCRIBE": (0, None),
        "UNWATCH": (0, 0),
        "WAIT": (2, 2),
        "WATCH": (1, None),
        "ZADD": (3, None),
        "ZCARD": (1, 1),
        "ZCOUNT": (3, 3),
        "ZINCRBY": (3, 3),
        "ZINTERSTORE": (3, None),
        "ZLEXCOUNT": (3, 3),
        "ZRANGE": (3, None),
        "ZRANGEBYLEX": (3, None),
        "ZRANGEBYSCORE": (3, None),
        "ZRANK": (2, 2),
        "ZREM": (2, None),
        "ZREMRANGEBYLEX": (3, 3),
        "ZREMRANGEBYRANK": (3, 3),
        "ZREMRANGEBYSCORE": (3, 3),
        "ZREVRANGE": (3, None),
        "ZREVRANGEBYLEX": (3, None),
        "ZREVRANGEBYSCORE": (3, None),
        "ZREVRANK": (2, 2),
        "ZSCAN": (2, None),
        "ZSCORE": (2, 2),
        "ZUNIONSTORE": (3, None),
    }

    def _buildResponseAndSend(self, input_cmd, input_args):
        try:
            input_cmd = input_cmd.upper()

            if input_cmd not in self.COMMANDS:
                raise UnknownCommandError(input_cmd)

            arg_min_count = self.COMMANDS[input_cmd][0]
            arg_max_count = self.COMMANDS[input_cmd][1]
            input_arg_count = len(input_args)

            if input_arg_count < arg_min_count or (
                arg_max_count is not None and input_arg_count > arg_max_count
            ):
                raise ArgumentCountError(input_cmd)

            if input_cmd == "QUIT":
                self.transport.write("+OK\r\n")
                self.transport.loseConnection()
                return

            if input_cmd == "AUTH":
                raise AuthenticationError()

            raise AuthenticationRequiredError()

        except (
            UnknownCommandError,
            ArgumentCountError,
            AuthenticationError,
            AuthenticationRequiredError,
        ) as e:
            self._logAlert(input_cmd, input_args)
            self.transport.write(e.message)
        return

    def _logAlert(self, cmd, args):
        args = " ".join(args)
        if len(args) > self.factory.max_arg_length:
            args = (
                args[: self.factory.max_arg_length]
                + "(and "
                + str(self.factory.max_arg_length - len(args))
                + " more bytes)"
            )
        logdata = {"CMD": cmd, "ARGS": args}
        self.factory.log(logdata, transport=self.transport)

    def _processRedisCommand(  # noqa: C901
        self,
    ):
        def _parseInlineCommand(cmd_string):
            try:
                tokens = shlex.split(cmd_string)
                if len(tokens) == 0:
                    cmd = ""
                    args = ""
                else:
                    cmd = tokens[0]
                    args = tokens[1:]
                return cmd, args, ""
            except ValueError:
                raise ProtocolError("unbalanced quotes in request")

        def _parseRESPArray(cmd_string):
            """
            RESP arrays with strings looks like:
                *<element_count>\r\n
                $<string_1_length>\r\n
                <string_1>\r\n
                $<string_2_length\r\n
                <string_2>\r\n
            """
            array = []

            if cmd_string[0] != "*":
                raise ProtocolError("expected '*', got '{c}'".format(c=cmd_string[0]))

            curr_ptr = cmd_string.find("\r\n")
            if curr_ptr == -1:
                raise RedisCommandAgain()

            arr_count = cmd_string[1:curr_ptr]
            curr_ptr += 2  # skip past CRLF
            try:
                arr_count = int(arr_count)
            except ValueError:
                raise ProtocolError("invalid multibulk length")

            for element_number in range(0, arr_count):
                elem_str, new_ptr = _parseRESPString(cmd_string[curr_ptr:])
                array.append(elem_str)
                curr_ptr += new_ptr

            return array, curr_ptr

        def _parseRESPString(cmd_string):
            if cmd_string[0] != "$":
                raise ProtocolError("expected '$', got '{c}'".format(c=cmd_string[0]))

            curr_ptr = cmd_string.find("\r\n")
            if curr_ptr == -1:
                raise RedisCommandAgain()

            str_length = cmd_string[1:curr_ptr]
            curr_ptr += 2  # skip past CRLF
            try:
                str_length = int(str_length)
            except ValueError:
                raise ProtocolError("invalid bulk length")

            resp_str = cmd_string[
                curr_ptr : (curr_ptr + str_length + 2)  # noqa: E203
            ]  # string + CRLF
            if len(resp_str) + 2 < str_length or resp_str[-2:] != "\r\n":
                raise RedisCommandAgain()

            curr_ptr += str_length + 2  # string + trailing CRLF
            return resp_str[:-2], curr_ptr

        def _parseRESPCommand(cmd_string):
            cmd = ""
            args = []
            if cmd_string[0] == "*":
                try:
                    array, curr_ptr = _parseRESPArray(cmd_string)
                except IndexError:
                    raise RedisCommandAgain()
            else:
                raise ProtocolError("expected '$', got '{c}'".format(c=cmd_string[0]))
            # print array
            cmd = array[0]
            args = array[1:]
            unfinished_data = cmd_string[curr_ptr:]

            return cmd, args, unfinished_data

        commands = []
        while len(self._data) > 0:
            if self._data[0] == "*":
                # print self._data
                cmd, args, self._data = _parseRESPCommand(self._data)
                # print cmd, args
            else:
                cmd, args, self._data = _parseInlineCommand(self._data)
            commands.append((cmd, args))

        return commands

    def dataReceived(self, data):
        """
        Received data is unbuffered so we buffer it for telnet.
        """
        try:
            try:
                # A command split over multiple packets is collected into a single
                # string until it can all be processed. If multiple commands
                # are in a single packet and missing some data, run again

                if not hasattr(self, "_data"):
                    self._data = data.decode()
                else:
                    self._data += data.decode()

                cmds = self._processRedisCommand()

                for cmd, args in cmds:
                    self._buildResponseAndSend(cmd, args)

            except RedisCommandAgain:
                pass

        except ProtocolError as e:
            self._errorAndClose(e.message)
            return

    def _errorAndClose(self, error_msg):
        self.transport.write(error_msg + "\r\n")
        self.transport.loseConnection()


class CanaryRedis(Factory, CanaryService):
    NAME = "redis"
    protocol = RedisProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.port = config.getVal("redis.port", default=6379)
        self.max_arg_length = config.getVal("redis.max_arg_length", default=30)
        self.logtype = logger.LOG_REDIS_COMMAND

    def getService(self):
        return internet.TCPServer(self.port, self, interface=self.listen_addr)
