import socket
import time

import pytest
from twisted.conch.telnet import IAC, NAWS, SB
from twisted.internet.error import ConnectionDone
from twisted.internet.task import Clock
from twisted.internet.testing import StringTransport
from twisted.python.failure import Failure

from helpers import get_log_count, get_matching_log
from opencanary.logger import LoggerBase
from opencanary.modules.telnet import (
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_TIMEOUT,
    MAX_SUBNEGOTIATION_BYTES,
    SUBNEGOTIATION_LIMIT_ERROR,
    Telnet,
)

TELNET_PORT = 23


def get_telnet_log(start_line, logtype):
    def is_matching_log(log):
        return log.get("logtype") == logtype and log.get("dst_port") == TELNET_PORT

    return get_matching_log(start_line, is_matching_log)


class TelnetTestConfig:
    def __init__(self, settings=None):
        self.settings = settings or {}

    def getVal(self, key, default=None):
        return self.settings.get(key, default)


class TelnetTestLogger:
    LOG_TELNET_CONNECTION_MADE = LoggerBase.LOG_TELNET_CONNECTION_MADE
    LOG_TELNET_LOGIN_ATTEMPT = LoggerBase.LOG_TELNET_LOGIN_ATTEMPT

    def __init__(self):
        self.events = []

    def log(self, event):
        self.events.append(event)


def build_telnet_factory(settings=None):
    logger = TelnetTestLogger()
    service = Telnet(config=TelnetTestConfig(settings), logger=logger)
    service.reactor = Clock()
    factory = service.getService().args[1]
    return factory, logger


def connect_telnet(factory):
    wrapper = factory.buildProtocol(None)
    transport = StringTransport()
    wrapper.makeConnection(transport)
    transport.clear()
    return wrapper.wrappedProtocol, transport


def test_telnet_connection_and_login_attempt_are_logged():
    """
    Connect and submit credentials to telnet service.
    """
    # Assumes that telnet.log_tcp_connection is enabled in the test configuration
    log_start = get_log_count()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(("localhost", TELNET_PORT))
        time.sleep(0.1)
        _ = connection.recv(4096)
        connection.sendall(b"test_user\r\n")
        time.sleep(0.1)
        connection.sendall(b"test_pass\r\n")

    login_log = get_telnet_log(log_start, LoggerBase.LOG_TELNET_LOGIN_ATTEMPT)
    assert login_log is not None
    assert login_log["logdata"]["USERNAME"] == "test_user"
    assert login_log["logdata"]["PASSWORD"] == "test_pass"

    connection_log = get_telnet_log(log_start, LoggerBase.LOG_TELNET_CONNECTION_MADE)
    assert connection_log is not None


def test_subnegotiation_buffer_limit_logs_error_and_closes():
    factory, logger = build_telnet_factory()
    protocol, transport = connect_telnet(factory)

    protocol.dataReceived(IAC + SB + NAWS + b"A" * (MAX_SUBNEGOTIATION_BYTES - 2))

    assert protocol.state == "subnegotiation"
    assert len(protocol.commands) == MAX_SUBNEGOTIATION_BYTES - 1
    assert not transport.disconnecting

    protocol.dataReceived(b"A")

    assert transport.disconnecting
    assert protocol.commands == []
    assert protocol.timeOut is None
    assert logger.events[-1]["logdata"] == {"ERROR": SUBNEGOTIATION_LIMIT_ERROR}


def test_large_subnegotiation_chunk_never_exceeds_buffer_limit():
    factory, logger = build_telnet_factory()
    protocol, transport = connect_telnet(factory)

    protocol.dataReceived(IAC + SB + NAWS + b"A" * (64 * 1024))

    assert transport.disconnecting
    assert protocol.commands == []
    assert len(logger.events) == 1


def test_telnet_default_limits():
    factory, _ = build_telnet_factory()

    assert factory.connectionLimit == DEFAULT_MAX_CONNECTIONS == 64
    assert factory.timeout == DEFAULT_TIMEOUT == 120


def test_telnet_custom_limits():
    factory, _ = build_telnet_factory(
        {"telnet.max_connections": 2, "telnet.timeout": 15.5}
    )

    assert factory.connectionLimit == 2
    assert factory.timeout == 15.5


@pytest.mark.parametrize("limit", [DEFAULT_MAX_CONNECTIONS, 2])
def test_telnet_connection_limit_and_slot_release(limit):
    settings = (
        {} if limit == DEFAULT_MAX_CONNECTIONS else {"telnet.max_connections": limit}
    )
    factory, _ = build_telnet_factory(settings)
    protocols = [factory.buildProtocol(None) for _ in range(limit)]

    assert all(protocol is not None for protocol in protocols)
    assert factory.connectionCount == limit
    assert factory.buildProtocol(None) is None

    protocols[0].connectionLost(Failure(ConnectionDone()))
    assert factory.connectionCount == limit - 1
    assert factory.buildProtocol(None) is not None
    assert factory.connectionCount == limit


@pytest.mark.parametrize("timeout", [DEFAULT_TIMEOUT, 5.5])
def test_telnet_inactive_connection_times_out(timeout):
    factory, _ = build_telnet_factory({"telnet.timeout": timeout})
    protocol, transport = connect_telnet(factory)

    factory.reactor.advance(timeout)

    assert transport.disconnecting
    assert protocol.timeOut is None


def test_telnet_data_resets_inactivity_timeout():
    factory, _ = build_telnet_factory({"telnet.timeout": 120})
    protocol, transport = connect_telnet(factory)

    factory.reactor.advance(119)
    protocol.dataReceived(b"A")
    factory.reactor.advance(119)
    assert not transport.disconnecting

    factory.reactor.advance(1)
    assert transport.disconnecting
