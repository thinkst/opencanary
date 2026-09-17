from unittest.mock import Mock

import git
import pytest
from twisted.internet.error import ConnectionDone
from twisted.internet.task import Clock
from twisted.internet.testing import StringTransport
from twisted.python.failure import Failure

from helpers import get_last_log
from opencanary.logger import LoggerBase
from opencanary.modules.git import CanaryGit, GitProtocol, MAX_PACKET_SIZE


@pytest.fixture
def git_repo():
    repo = git.Repo
    yield repo


def test_clone_a_repository(git_repo):
    with pytest.raises(git.exc.GitCommandError):
        git_repo.clone_from("git://localhost/test.git", "/tmp/git_test")


def test_log_git_clone(git_repo):
    """
    Check that the git clone attempt was logged
    """
    # This test assumes a prior clone attempt has already been made.
    # Otherwise, trigger one here or in shared test setup.
    last_log = get_last_log()
    assert "localhost" in last_log["logdata"]["HOST"]
    assert last_log["logdata"]["REPO"] == "test.git"


class GitTestFactory:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.reactor = Clock()
        self.logs = []

    def log(self, logdata, transport=None):
        self.logs.append(logdata)


def build_git_protocol(timeout=10):
    protocol = GitProtocol()
    protocol.factory = GitTestFactory(timeout=timeout)
    protocol.makeConnection(StringTransport())
    return protocol


def git_packet(project="test.git", host="localhost"):
    command = f"git-upload-pack /{project}\0host={host}\0".encode()
    return f"{len(command) + 4:04x}".encode() + command


def git_service(**settings):
    config = Mock()
    config.getVal.side_effect = lambda key, default=None: settings.get(key, default)
    logger = Mock(spec=["log", "LOG_GIT_CLONE_REQUEST"])
    logger.LOG_GIT_CLONE_REQUEST = LoggerBase.LOG_GIT_CLONE_REQUEST
    service = CanaryGit(config=config, logger=logger)
    service.reactor = Clock()
    return service


def test_git_packet_header_can_be_split_across_reads():
    protocol = build_git_protocol()
    packet = git_packet()

    protocol.dataReceived(packet[:2])
    assert not protocol.transport.disconnecting
    assert protocol.transport.value() == b""

    protocol.dataReceived(packet[2:])
    assert not protocol.transport.disconnecting
    assert protocol.factory.logs == [{"REPO": "test.git", "HOST": "localhost"}]
    assert protocol.transport.value()[4:].startswith(b"ERR no such repository:")


def test_git_rejects_more_than_maximum_packet_size():
    protocol = build_git_protocol()

    protocol.dataReceived(b"x" * (MAX_PACKET_SIZE + 1))

    assert protocol.transport.disconnecting
    assert protocol._data == b""
    assert protocol.timeOut is None


def test_git_accepts_exactly_maximum_packet_size_then_rejects_more_data():
    protocol = build_git_protocol()
    command = b"git-upload-pack /test.git\0host=localhost\0"
    command += b"x" * (MAX_PACKET_SIZE - 4 - len(command))
    packet = b"fff0" + command

    protocol.dataReceived(packet)

    assert len(packet) == MAX_PACKET_SIZE
    assert not protocol.transport.disconnecting
    assert protocol.factory.logs[0]["REPO"] == "test.git"
    assert protocol._data == b""

    protocol.dataReceived(b"x")
    assert protocol.transport.disconnecting


def test_git_rejects_declared_packet_length_above_limit_immediately():
    protocol = build_git_protocol()

    protocol.dataReceived(b"ffff")

    assert protocol.transport.disconnecting
    assert protocol._data == b""


@pytest.mark.parametrize("timeout", [10, 3.5])
def test_git_inactive_connection_times_out(timeout):
    protocol = build_git_protocol(timeout=timeout)

    protocol.factory.reactor.advance(timeout)

    assert protocol.transport.disconnecting
    assert protocol.timeOut is None


def test_git_activity_resets_timeout():
    protocol = build_git_protocol(timeout=10)

    protocol.factory.reactor.advance(9)
    protocol.dataReceived(b"0")
    protocol.factory.reactor.advance(9)
    assert not protocol.transport.disconnecting

    protocol.factory.reactor.advance(1)
    assert protocol.transport.disconnecting


def test_git_default_settings():
    service = git_service()

    assert service.connectionLimit == 32
    assert service.timeout == 10


def test_git_custom_settings():
    service = git_service(**{"git.max_connections": 2, "git.timeout": 4.5})

    assert service.connectionLimit == 2
    assert service.timeout == 4.5


@pytest.mark.parametrize("limit", [32, 2])
def test_git_connection_limit_and_slot_release(limit):
    settings = {} if limit == 32 else {"git.max_connections": limit}
    service = git_service(**settings)
    protocols = [service.buildProtocol(None) for _ in range(limit)]

    assert all(protocol is not None for protocol in protocols)
    assert service.connectionCount == limit
    assert service.buildProtocol(None) is None

    protocols[0].connectionLost(Failure(ConnectionDone()))
    assert service.connectionCount == limit - 1
    replacement = service.buildProtocol(None)
    assert replacement is not None
    assert service.connectionCount == limit
