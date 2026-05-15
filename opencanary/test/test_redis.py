import pytest
import redis

from helpers import get_log_count, get_matching_log
from opencanary.logger import LoggerBase

REDIS_PORT = 6379
REDIS_HOST = "localhost"
REDIS_TIMEOUT = 2
REDIS_LOG_TYPE = LoggerBase.LOG_REDIS_COMMAND


def get_redis_client(**kwargs):
    return redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        socket_connect_timeout=REDIS_TIMEOUT,
        socket_timeout=REDIS_TIMEOUT,
        decode_responses=True,
        **kwargs,
    )


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
