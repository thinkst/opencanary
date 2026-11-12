import pytest
from twisted.conch.telnet import IAC, NAWS, SB
from twisted.internet.error import ConnectionDone
from twisted.internet.task import Clock
from twisted.internet.testing import StringTransport
from twisted.python.failure import Failure

from opencanary.logger import LoggerBase
from opencanary.modules.telnet import (
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_TIMEOUT,
    MAX_SUBNEGOTIATION_BYTES,
    SUBNEGOTIATION_LIMIT_ERROR,
    Telnet,
)


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
