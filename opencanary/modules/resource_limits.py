"""Shared limits for TCP honeypots running on the same reactor."""

import math

from twisted.internet import reactor
from twisted.protocols.policies import ProtocolWrapper, WrappingFactory

from opencanary.config import ConfigException


def positive_setting(config, key, default, integer=False, allow_zero=False):
    value = config.getVal(key, default=default)
    try:
        number = float(value)
        if (
            isinstance(value, bool)
            or not math.isfinite(number)
            or number < 0
            or (number == 0 and not allow_zero)
        ):
            raise ValueError()
        if integer and number != int(number):
            raise ValueError()
    except (TypeError, ValueError, OverflowError):
        requirement = "non-negative" if allow_zero else "positive"
        raise ConfigException(key, "Must be a finite %s number" % requirement)
    return int(number) if integer else number


class ResourceBoundedProtocol(ProtocolWrapper):
    def connectionMade(self):
        self._idle_call = self.factory.reactor.callLater(
            self.factory.timeout, self._expire
        )
        self._deadline_call = None
        if self.factory.max_duration:
            self._deadline_call = self.factory.reactor.callLater(
                self.factory.max_duration, self._expire
            )

    def _cancel_timers(self):
        for name in ("_idle_call", "_deadline_call"):
            call = getattr(self, name, None)
            if call is not None and call.active():
                call.cancel()

    def _expire(self):
        self.abortConnection()

    def abortConnection(self):
        self._cancel_timers()
        self.disconnecting = True
        # Do not wait for a client to drain queued output before releasing its FD.
        self.transport.abortConnection()

    def dataReceived(self, data):
        if self.disconnecting:
            return
        if data:
            self._idle_call.reset(self.factory.timeout)
        super().dataReceived(data)

    def connectionLost(self, reason):
        self._cancel_timers()
        super().connectionLost(reason)


class BoundedConnectionFactory(WrappingFactory):
    """Bound accepted connections, idle time and total connection lifetime."""

    def __init__(
        self,
        wrappedFactory,
        config,
        prefix,
        *,
        default_max_connections=32,
        default_timeout=10,
        default_max_duration=60,
    ):
        """Use service defaults unless config overrides them; duration 0 is unlimited."""
        super().__init__(wrappedFactory)
        self.reactor = reactor
        self.connectionLimit = positive_setting(
            config, prefix + ".max_connections", default_max_connections, integer=True
        )
        self.timeout = positive_setting(config, prefix + ".timeout", default_timeout)
        self.max_duration = positive_setting(
            config, prefix + ".max_duration", default_max_duration, allow_zero=True
        )
        self.connectionCount = 0

    def buildProtocol(self, addr):
        if self.connectionCount >= self.connectionLimit:
            return None
        protocol = self.wrappedFactory.buildProtocol(addr)
        if protocol is None:
            return None
        self.connectionCount += 1
        return ResourceBoundedProtocol(self, protocol)

    def unregisterProtocol(self, protocol):
        super().unregisterProtocol(protocol)
        self.connectionCount -= 1
