"""Exercise the production listener factories with deterministic time."""

from unittest.mock import Mock

import pytest
from twisted.internet.error import ConnectionDone
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.task import Clock
from twisted.internet.testing import StringTransport
from twisted.python.failure import Failure

from opencanary.config import ConfigException
from opencanary.modules.resource_limits import BoundedConnectionFactory


def connect(factory):
    protocol = factory.buildProtocol(None)
    if protocol is not None:
        protocol.makeConnection(StringTransport())
    return protocol


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
