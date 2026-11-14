"""Exercise the production listener factories with deterministic time."""

import struct
from unittest.mock import Mock

import pytest
from twisted.internet.error import ConnectionDone
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.task import Clock
from twisted.internet.testing import StringTransport
from twisted.python.failure import Failure

from opencanary.config import ConfigException
from opencanary.logger import PyLogger
from opencanary.modules.mysql import CanaryMySQL
from opencanary.modules.rdp import CanaryRDP
from opencanary.modules.resource_limits import BoundedConnectionFactory
from opencanary.modules.vnc import CanaryVNC

SERVICES = [
    ("rdp", CanaryRDP),
    ("vnc", CanaryVNC),
    ("mysql", CanaryMySQL),
]


def listener_factory(service_class, settings=None):
    settings = {"tcpbanner_1.enabled": True, **(settings or {})}
    config = Mock()
    config.getVal.side_effect = lambda key, default=None: settings.get(key, default)
    service = service_class(config=config, logger=Mock(spec=PyLogger))
    listener = service.getService()
    if isinstance(listener, list):
        listener = listener[0]
    factory = listener.args[1]
    factory.reactor = Clock()
    return factory


def connect(factory):
    protocol = factory.buildProtocol(None)
    if protocol is not None:
        protocol.makeConnection(StringTransport())
    return protocol


@pytest.mark.parametrize("prefix,service_class", SERVICES)
@pytest.mark.parametrize("configured_limit", [None, 2])
def test_connection_limit_and_release(prefix, service_class, configured_limit):
    default_limit = 32
    limit = default_limit if configured_limit is None else configured_limit
    settings = {} if configured_limit is None else {prefix + ".max_connections": limit}
    factory = listener_factory(service_class, settings)
    protocols = [connect(factory) for _ in range(limit)]
    assert all(protocols)
    assert factory.connectionCount == limit
    assert connect(factory) is None

    protocols.pop().connectionLost(Failure(ConnectionDone()))
    assert factory.connectionCount == limit - 1
    assert connect(factory) is not None
    assert factory.connectionCount == limit


@pytest.mark.parametrize("prefix,service_class", SERVICES)
@pytest.mark.parametrize("timeout", [10, 2.5])
def test_idle_connections_expire(prefix, service_class, timeout):
    factory = listener_factory(service_class, {prefix + ".timeout": timeout})
    protocol = connect(factory)
    factory.reactor.advance(timeout - 0.1)
    assert not protocol.transport.disconnecting
    factory.reactor.advance(0.1)
    assert protocol.transport.disconnected
    assert factory.reactor.getDelayedCalls() == []
    protocol.connectionLost(Failure(ConnectionDone()))
    assert factory.connectionCount == 0


@pytest.mark.parametrize("prefix,service_class", SERVICES)
def test_disconnect_cancels_timers_and_clears_buffers(prefix, service_class):
    factory = listener_factory(service_class)
    protocol = connect(factory)
    inner = protocol.wrappedProtocol
    protocol.connectionLost(Failure(ConnectionDone()))
    assert factory.reactor.getDelayedCalls() == []
    assert factory.connectionCount == 0
    if hasattr(inner, "_buffer"):
        assert inner._buffer == b""
    if hasattr(inner, "buffer"):
        assert inner.buffer == b""


@pytest.mark.parametrize("prefix,service_class", SERVICES)
def test_active_connections_still_have_absolute_deadline(prefix, service_class):
    factory = listener_factory(service_class, {prefix + ".max_duration": 25})
    protocol = connect(factory)
    # Isolate the wrapper's lifetime policy from individual wire protocols.
    protocol.wrappedProtocol.dataReceived = Mock()
    for _ in range(3):
        factory.reactor.advance(8)
        protocol.dataReceived(b"x")
        assert not protocol.transport.disconnecting
    factory.reactor.advance(1)
    assert protocol.transport.disconnected
    assert factory.reactor.getDelayedCalls() == []


@pytest.mark.parametrize(
    "prefix,service_class",
    [
        (prefix, cls)
        for prefix, cls in SERVICES
        if cls in (CanaryRDP, CanaryVNC, CanaryMySQL)
    ],
)
def test_default_deadline_cannot_be_extended(prefix, service_class):
    factory = listener_factory(service_class)
    protocol = connect(factory)
    protocol.wrappedProtocol.dataReceived = Mock()
    for _ in range(7):
        factory.reactor.advance(8)
        protocol.dataReceived(b"x")
    factory.reactor.advance(4)
    assert protocol.transport.disconnected


@pytest.mark.parametrize("service_class", [CanaryMySQL])
def test_slow_sql_packets_obey_configured_deadline(service_class):
    prefix = "mysql" if service_class is CanaryMySQL else "mssql"
    factory = listener_factory(service_class, {prefix + ".max_duration": 60})
    protocol = connect(factory)
    # Valid headers for incomplete MySQL auth / TDS prelogin messages.
    header = (
        b"\xfc\xff\x00\x01"
        if service_class is CanaryMySQL
        else struct.pack(">BBHHBB", 18, 1, 65535, 0, 1, 0)
    )
    protocol.dataReceived(header)
    for _ in range(6):
        factory.reactor.advance(9)
        protocol.dataReceived(b"\x00")
        assert not protocol.transport.disconnecting
    factory.reactor.advance(6)
    assert protocol.transport.disconnected


@pytest.mark.parametrize("service_class,limit", [(CanaryMySQL, 65536)])
def test_sql_receive_buffer_is_bounded(service_class, limit):
    protocol = connect(listener_factory(service_class))
    protocol.dataReceived(b"x" * (limit + 1))
    assert protocol.transport.disconnected
    assert protocol.wrappedProtocol._buffer == b""


def test_mysql_rejects_oversized_declared_length_without_buffering_payload():
    protocol = connect(listener_factory(CanaryMySQL))
    protocol.dataReceived(b"\xff\xff\xff\x01")
    assert protocol.transport.disconnected
    assert protocol.wrappedProtocol._buffer == b""


@pytest.mark.parametrize("option", ["max_connections", "timeout", "max_duration"])
@pytest.mark.parametrize("value", [-1, None, True, float("inf"), float("nan"), "bad"])
def test_invalid_limits_are_rejected(option, value):
    with pytest.raises(ConfigException):
        listener_factory(CanaryRDP, {"rdp." + option: value})


def test_fractional_connection_limit_is_rejected():
    with pytest.raises(ConfigException):
        listener_factory(CanaryRDP, {"rdp.max_connections": 1.5})


@pytest.mark.parametrize("configured", [False, True])
def test_service_defaults_and_configuration_precedence(configured):
    config = Mock()
    settings = (
        {"test.max_connections": 1, "test.timeout": 5, "test.max_duration": 20}
        if configured
        else {}
    )
    config.getVal.side_effect = lambda key, default=None: settings.get(key, default)
    wrapped = Factory()
    wrapped.protocol = Protocol
    factory = BoundedConnectionFactory(
        wrapped,
        config,
        "test",
        default_max_connections=2,
        default_timeout=15,
        default_max_duration=40,
    )
    factory.reactor = Clock()
    limit, timeout, duration = (1, 5, 20) if configured else (2, 15, 40)
    assert (factory.connectionLimit, factory.timeout, factory.max_duration) == (
        limit,
        timeout,
        duration,
    )
    protocols = [connect(factory) for _ in range(limit)]
    assert connect(factory) is None
    factory.reactor.advance(timeout)
    assert all(protocol.transport.disconnected for protocol in protocols)

    for protocol in protocols:
        protocol.connectionLost(Failure(ConnectionDone()))
    protocol = connect(factory)
    elapsed = 0
    while elapsed + timeout / 2 < duration:
        factory.reactor.advance(timeout / 2)
        elapsed += timeout / 2
        protocol.dataReceived(b"x")
        assert not protocol.transport.disconnecting
    factory.reactor.advance(duration - elapsed)
    assert protocol.transport.disconnected


@pytest.mark.parametrize(
    "defaults",
    [
        {"default_max_connections": 1.5},
        {"default_timeout": 0},
        {"default_max_duration": float("inf")},
    ],
)
def test_service_defaults_are_validated(defaults):
    config = Mock()
    config.getVal.side_effect = lambda key, default=None: default
    with pytest.raises(ConfigException):
        BoundedConnectionFactory(Factory(), config, "test", **defaults)


@pytest.mark.parametrize("prefix,service_class", SERVICES)
def test_zero_configuration_disables_lifetime_limit(prefix, service_class):
    factory = listener_factory(service_class, {prefix + ".max_duration": 0})
    protocol = connect(factory)
    protocol.wrappedProtocol.dataReceived = Mock()
    assert protocol._deadline_call is None
    for _ in range(20):
        factory.reactor.advance(9)
        protocol.dataReceived(b"x")
        assert not protocol.transport.disconnecting
    protocol.connectionLost(Failure(ConnectionDone()))
    assert factory.reactor.getDelayedCalls() == []


@pytest.mark.parametrize("option", ["max_connections", "timeout"])
def test_zero_connection_cap_or_idle_timeout_is_rejected(option):
    with pytest.raises(ConfigException):
        listener_factory(CanaryRDP, {"rdp." + option: 0})
