import pytest
import redis
from unittest.mock import Mock

from twisted.internet.task import Clock
from twisted.internet.testing import StringTransport

from helpers import get_log_count, get_matching_log
from opencanary.logger import LoggerBase
from opencanary.modules.redis import CanaryRedis

REDIS_PORT = 6379
REDIS_HOST = "localhost"
REDIS_TIMEOUT = 2
REDIS_LOG_TYPE = LoggerBase.LOG_REDIS_COMMAND


class StringTransportWithDisconnect(StringTransport):
    def loseWriteConnection(self):
        self.loseConnection()


def get_redis_client(**kwargs):
    client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        socket_connect_timeout=REDIS_TIMEOUT,
        socket_timeout=REDIS_TIMEOUT,
        decode_responses=True,
        driver_info=redis.driver_info.DriverInfo(name="", lib_version=""),
        **kwargs,
    )
    return client


def get_redis_log(start_line, command, args=None):
    args = args or ""

    def is_matching_log(log):
        if log.get("dst_port") != REDIS_PORT:
            return False
        if log.get("logdata", {}).get("CMD") != command:
            return False
        if args and args not in log.get("logdata", {}).get("ARGS", ""):
            return False
        return True

    return get_matching_log(start_line, is_matching_log)


@pytest.fixture
def log_start():
    return get_log_count()


@pytest.fixture
def redis_factory():
    protocols = []

    def build(**settings):
        config = Mock()
        config.getVal.side_effect = lambda key, default=None: settings.get(key, default)
        logger = Mock(spec=["log", "LOG_REDIS_COMMAND"])
        logger.LOG_REDIS_COMMAND = REDIS_LOG_TYPE
        factory = CanaryRedis(config=config, logger=logger)
        factory.reactor = Clock()

        def connect():
            protocol = factory.buildProtocol(None)
            protocol.makeConnection(StringTransportWithDisconnect())
            protocols.append(protocol)
            return protocol

        return factory, connect

    yield build

    for protocol in protocols:
        protocol.connectionLost(None)


def test_redis_requires_authentication(log_start):
    """
    Redis should reject unauthenticated commands.
    """
    client = get_redis_client()

    with pytest.raises(redis.exceptions.AuthenticationError):
        client.ping()

    log = get_redis_log(log_start, "PING")
    assert log is not None
    assert log["logtype"] == REDIS_LOG_TYPE
    assert log["dst_port"] == REDIS_PORT
    assert log["logdata"]["CMD"] == "PING"


def test_redis_auth_attempt_is_logged(log_start):
    """
    Redis should reject authentication and log the attempt.
    """
    client = get_redis_client(password="test_pass")

    with pytest.raises(redis.exceptions.AuthenticationError):
        client.ping()

    log = get_redis_log(log_start, "AUTH", "test_pass")
    assert log is not None
    assert log["logtype"] == REDIS_LOG_TYPE
    assert log["dst_port"] == REDIS_PORT
    assert log["logdata"]["CMD"] == "AUTH"
    assert "test_pass" in log["logdata"]["ARGS"]


def test_redis_unknown_command_is_logged(log_start):
    """
    Unknown commands should be rejected and logged.
    """
    client = get_redis_client()

    with pytest.raises(redis.exceptions.ResponseError):
        client.execute_command("CANARY_UNKNOWN")

    log = get_redis_log(log_start, "CANARY_UNKNOWN")
    assert log is not None
    assert log["logtype"] == REDIS_LOG_TYPE
    assert log["dst_port"] == REDIS_PORT
    assert log["logdata"]["CMD"] == "CANARY_UNKNOWN"


def assert_redis_limit_error(protocol, reason):
    assert protocol.transport.disconnecting
    assert protocol.transport.value() == (f"-ERR Protocol error: {reason}\r\n".encode())
    assert protocol._data == b""
    event = protocol.factory.logger.log.call_args.args[0]
    assert event["logtype"] == REDIS_LOG_TYPE
    assert event["logdata"]["ERROR"].startswith(reason)
    if protocol._error_close_call is not None and protocol._error_close_call.active():
        protocol._error_close_call.cancel()
    assert not protocol.factory.reactor.getDelayedCalls()


@pytest.mark.parametrize(
    "setting,accepted,rejected,reason,alternate_response,should_disconnect",
    [
        (
            {},
            b"*10\r\n$1\r\nx\r\n$1\r\nx\r\n$1\r\nx\r\n$1\r\nx\r\n$1\r\nx\r\n$1\r\nx\r\n$1\r\nx\r\n$1\r\nx\r\n$1\r\nx\r\n$1\r\nx\r\n",
            b"*11\r\n",
            "unauthenticated multibulk length",
            b"-ERR unknown command 'x', with args beginning with: 'x' 'x' 'x' 'x' 'x' 'x' 'x' 'x' 'x' \r\n",
            True,
        ),
        (
            {},
            b"*2\r\n$3\r\nGET\r\n$1\r\nx\r\n",
            b"*a\r\n",
            "invalid multibulk length",
            None,
            True,
        ),
        (
            {},
            b"*1\r\n$16384\r\n" + b"A" * 16384 + b"\r\n",
            b"*1\r\n$16385\r\n" + b"A" * 16385 + b"\r\n",
            "invalid bulk length",
            b"-ERR unknown command 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', with args beginning with: \r\n",
            False,
        ),
        (
            {},
            b"A" * 65536,
            b"A" * 65537,
            "too big inline request",
            b"",
            False,
        ),
    ],
    ids=["array", "invalid-length", "bulk-string", "inline-command"],
)
def test_redis_limit_boundaries(
    redis_factory,
    setting,
    accepted,
    rejected,
    reason,
    alternate_response,
    should_disconnect,
):
    factory, connect = redis_factory(**setting)
    protocol = connect()
    protocol.dataReceived(accepted)
    assert not protocol.transport.disconnecting

    if alternate_response is not None:
        assert protocol.transport.value() == alternate_response
    else:
        assert protocol.transport.value() == b"-NOAUTH Authentication required.\r\n"

    if (
        hasattr(factory.logger.log.call_args, "args")
        and factory.logger.log.call_args.args
    ):
        assert "ERROR" not in factory.logger.log.call_args.args[0]["logdata"]
    protocol.setTimeout(None)

    protocol = connect()
    protocol.dataReceived(rejected)
    protocol.setTimeout(None)
    if should_disconnect:
        assert_redis_limit_error(protocol, reason)


@pytest.mark.parametrize(
    "payload,reason",
    [
        (b"*99999999999999999999\r\n", "invalid multibulk length"),
        (b"*1\r\n$99999999999999999999\r\n", "invalid bulk length"),
    ],
)
def test_redis_rejects_excessive_length_digits(redis_factory, payload, reason):
    _, connect = redis_factory()
    protocol = connect()
    protocol.dataReceived(payload)
    protocol.setTimeout(None)
    assert_redis_limit_error(protocol, reason)


def test_redis_buffer_limit_counts_previous_fragments(redis_factory):
    factory, connect = redis_factory()
    protocol = connect()
    length = 2**14  # 16kb
    protocol.dataReceived(b"*1\r\n$%d\r\n" % length + b"x" * (length - 1))
    assert not protocol.transport.disconnecting
    assert protocol.transport.value() == b""
    assert factory.reactor.getDelayedCalls()

    protocol.dataReceived(b"x" * 1000)
    protocol.setTimeout(None)
    assert_redis_limit_error(protocol, "invalid bulk length")


@pytest.mark.parametrize(
    "payload, reason",
    [
        (b"X" * (64 * 1024 + 1), "too big inline request"),
        (b"*" + b"1" * (64 * 1024 + 1), "too big mbulk count string"),
        (b"*1\r\n$" + b"1" * (64 * 1024 + 1), "too big bulk count string"),
    ],
)
def test_redis_command_limit_applies_before_terminator(redis_factory, payload, reason):
    _, connect = redis_factory()
    protocol = connect()
    protocol.dataReceived(payload)
    protocol.setTimeout(None)
    assert_redis_limit_error(protocol, reason)


def test_redis_command_limit_counts_all_resp_elements(redis_factory):
    _, connect = redis_factory()
    protocol = connect()
    protocol.dataReceived(b"*2\r\n$3\r\nGET\r\n$1" + b"A" * (64 * 1024 - 10) + b"\r\n")
    protocol.setTimeout(None)
    assert_redis_limit_error(protocol, "invalid bulk length")


def test_redis_command_limit_is_per_command_in_pipeline(redis_factory):
    _, connect = redis_factory(**{"redis.max_command_bytes": 6})
    protocol = connect()
    protocol.dataReceived(b"PING\r\nPING\r\n")
    assert not protocol.transport.disconnecting
    assert protocol.transport.value() == b"-NOAUTH Authentication required.\r\n" * 2


def test_redis_idle_timeout(redis_factory):
    factory, connect = redis_factory(**{"redis.timeout": 5})
    protocol = connect()
    factory.reactor.advance(2)
    assert not protocol.transport.disconnecting
    factory.reactor.advance(10)
    assert protocol.transport.disconnecting
    assert protocol.transport.value() == b""
    assert protocol._data == b""
    protocol.setTimeout(None)
    assert not protocol.factory.reactor.getDelayedCalls()


def test_redis_timeout_restarts_for_more_data(redis_factory):
    factory, connect = redis_factory(**{"redis.timeout": 5})
    protocol = connect()
    assert not protocol.transport.disconnecting
    protocol.dataReceived(b"PI")
    factory.reactor.advance(4)
    assert not protocol.transport.disconnecting
    protocol.dataReceived(b"NG\r\n")
    assert factory.reactor.getDelayedCalls()
    # import pdb; pdb.set_trace()
    factory.reactor.advance(10)
    assert not factory.reactor.getDelayedCalls()
    assert protocol.transport.disconnecting


def test_redis_timeout_can_be_disabled(redis_factory):
    factory, connect = redis_factory(**{"redis.timeout": 0})
    protocol = connect()
    protocol.dataReceived(b"PI")
    factory.reactor.advance(100)
    assert not protocol.transport.disconnecting
    assert not factory.reactor.getDelayedCalls()


def test_redis_connection_limit_releases_only_accepted_connections(redis_factory):
    factory, connect = redis_factory(**{"redis.max_connections": 1})
    accepted = connect()
    assert not accepted.transport.disconnecting
    rejected = connect()
    assert rejected.transport.disconnecting
    assert factory.active_connections == 1
    assert factory.logger.log.call_args.args[0]["logdata"]["ERROR"] == (
        "max connections exceeded"
    )
    rejected.connectionLost(None)
    assert factory.active_connections == 1
    accepted.dataReceived(b"PI")
    accepted.connectionLost(None)
    assert factory.active_connections == 0
    assert not connect().transport.disconnecting
    assert factory.active_connections == 1


def test_redis_connection_limit_can_be_disabled(redis_factory):
    _, connect = redis_factory(**{"redis.max_connections": 0})
    for _ in range(3):
        assert not connect().transport.disconnecting


@pytest.mark.parametrize(
    "length,expected_command,expected_args",
    [
        pytest.param(4, "PING", "\u00e9\u00e9", id="complete-utf8-argument"),
        pytest.param(3, "PIN", "\u00e9\ufffd", id="truncated-utf8-argument"),
    ],
)
def test_redis_log_limit_counts_bytes(
    redis_factory, length, expected_command, expected_args
):
    factory, connect = redis_factory(**{"redis.max_arg_length": length})
    protocol = connect()
    protocol.dataReceived(b"*2\r\n$4\r\nPING\r\n$4\r\n\xc3\xa9\xc3\xa9\r\n")
    event = factory.logger.log.call_args.args[0]["logdata"]
    assert event["CMD"] == expected_command
    assert event["ARGS"] == expected_args
    assert not protocol.transport.disconnecting


def test_binary_bulk_string_is_logged_without_decode_crash(redis_factory):
    factory, connect = redis_factory()
    protocol = connect()

    protocol.dataReceived(b"*2\r\n$3\r\nGET\r\n$1\r\n\xff\r\n")

    event = factory.logger.log.call_args.args[0]["logdata"]
    assert event["CMD"] == "GET"
    assert event["ARGS"] == "\ufffd"
    assert not protocol.transport.disconnecting
    assert protocol.transport.value() == b"-NOAUTH Authentication required.\r\n"


@pytest.mark.parametrize(
    "settings,bulk_length,expected_error",
    [
        (
            {},
            999999999,
            "invalid bulk length",
        ),
        (
            {},
            2**20,
            "unauthenticated bulk length",
        ),
        (
            {},
            2**20 + 1,
            "invalid bulk length",
        ),
        (
            {},
            -1,
            "invalid bulk length",
        ),
        (
            {"redis.max_bulk_string_length": 2**16},
            2**16,
            "unauthenticated bulk length",
        ),
        (
            {"redis.max_bulk_string_length": 2**16},
            2**16 + 1,
            "invalid bulk length",
        ),
    ],
    ids=[
        "invalid",
        "unauthenticated",
        "exceeds-buf",
        "negative",
        "custom-bulk-ok",
        "custom-bulk-err",
    ],
)
def test_declared_bulk_length(settings, bulk_length, expected_error, redis_factory):
    factory, connect = redis_factory(**settings)
    protocol = connect()

    protocol.dataReceived(b"*1\r\n$%d\r\n" % bulk_length)

    assert protocol.transport.disconnecting is True
    assert (
        protocol.transport.value()
        == b"-ERR Protocol error: %s\r\n" % expected_error.encode()
    )
    assert protocol._data == b""
    event = protocol.factory.logger.log.call_args.args[0]
    assert event["logtype"] == REDIS_LOG_TYPE
    assert event["logdata"]["ERROR"].startswith(expected_error)


@pytest.mark.parametrize(
    "settings,array_length,expected_error",
    [
        (
            {},
            2**31 - 1,
            "unauthenticated multibulk length",
        ),
        (
            {},
            2**31,
            "invalid multibulk length",
        ),
        (
            {},
            "a",
            "invalid multibulk length",
        ),
    ],
    ids=["unauthenticated", "invalid-too-large", "not-digit"],
)
def test_declared_array_length(settings, array_length, expected_error, redis_factory):
    factory, connect = redis_factory(**settings)
    protocol = connect()

    # import pdb;pdb.set_trace()
    if isinstance(array_length, int):
        protocol.dataReceived(b"*%d\r\n" % array_length)
    else:
        protocol.dataReceived(b"*%s\r\n" % str(array_length).encode())

    assert protocol.transport.disconnecting is True
    assert (
        protocol.transport.value()
        == b"-ERR Protocol error: %s\r\n" % expected_error.encode()
    )
    assert protocol._data == b""
    event = protocol.factory.logger.log.call_args.args[0]
    assert event["logtype"] == REDIS_LOG_TYPE
    assert event["logdata"]["ERROR"].startswith(expected_error)


def test_wrong_argument_count_returns_error_without_uncaught_exception(redis_factory):
    _, connect = redis_factory()
    protocol = connect()

    protocol.dataReceived(b"*1\r\n$3\r\nGET\r\n")

    assert protocol.transport.disconnecting is False
    assert (
        protocol.transport.value()
        == b"-ERR wrong number of arguments for 'get' command\r\n"
    )
    event = protocol.factory.logger.log.call_args.args[0]
    assert event["logtype"] == REDIS_LOG_TYPE
    assert event["logdata"]["CMD"] == "GET"


def test_unknown_command_response_sanitizes_crlf(redis_factory):
    _, connect = redis_factory()
    protocol = connect()

    protocol.dataReceived(b"*1\r\n$7\r\nBAD\r\nOK\r\n")

    assert protocol.transport.disconnecting is False
    assert (
        protocol.transport.value()
        == b"-ERR unknown command 'BAD  OK', with args beginning with: \r\n"
    )
    assert b"\r" not in protocol.transport.value()[:-2]
    assert b"\n" not in protocol.transport.value()[:-2]
    event = protocol.factory.logger.log.call_args.args[0]
    assert event["logtype"] == REDIS_LOG_TYPE
    assert event["logdata"]["CMD"] == "BAD  OK"


@pytest.mark.parametrize(
    "payload,expected_response,expected_command,expected_args",
    [
        pytest.param(
            b"*1\r\n$1\r\n\xff\r\n",
            "-ERR unknown command '\ufffd', with args beginning with: \r\n",
            "\ufffd",
            "",
            id="non-utf8-command",
        ),
        pytest.param(
            b"*2\r\n$3\r\nBAD\r\n$1\r\n\xff\r\n",
            "-ERR unknown command 'BAD', with args beginning with: '\ufffd' \r\n",
            "BAD",
            "\ufffd",
            id="non-utf8-argument",
        ),
    ],
)
def test_unknown_command_handles_non_utf8_input(
    redis_factory,
    payload,
    expected_response,
    expected_command,
    expected_args,
):
    _, connect = redis_factory()
    protocol = connect()
    protocol.dataReceived(payload)

    event = protocol.factory.logger.log.call_args.args[0]
    assert event["logdata"]["CMD"] == expected_command
    assert event["logdata"]["ARGS"] == expected_args
    assert protocol.transport.value() == expected_response.encode("utf-8")
    assert protocol.transport.disconnecting is False


def test_inline_command_handles_non_utf8_input(redis_factory):
    _, connect = redis_factory()
    protocol = connect()
    protocol.dataReceived(b"\xff\r\n")

    event = protocol.factory.logger.log.call_args.args[0]
    assert event["logdata"]["CMD"] == "\ufffd"
    assert event["logdata"]["ARGS"] == ""
    assert (
        protocol.transport.value()
        == "-ERR unknown command '\ufffd', with args beginning with: \r\n".encode(
            "utf-8"
        )
    )
    assert not protocol.transport.disconnecting


def test_invalid_resp_element_handles_non_utf8_input(
    redis_factory,
):
    _, connect = redis_factory()
    protocol = connect()
    protocol.dataReceived(b"*1\r\n\xff\r\n")

    event = protocol.factory.logger.log.call_args.args[0]
    assert event["logdata"]["CMD"] == ""
    assert event["logdata"]["ARGS"] == ""
    assert (
        protocol.transport.value()
        == "-ERR Protocol error: expected '$', got '\ufffd'\r\n".encode("utf-8")
    )
    assert protocol.transport.disconnecting
