import pytest
import redis

from opencanary.logger import LoggerBase


def get_redis_client(service, **kwargs):
    return redis.Redis(
        host=service.host,
        port=service.port,
        socket_connect_timeout=2,
        socket_timeout=2,
        decode_responses=True,
        driver_info=redis.driver_info.DriverInfo(name="", lib_version=""),
        **kwargs,
    )


def get_redis_log(service, start, command):
    return service.get_matching_log(
        start,
        lambda event: event.get("logtype") == LoggerBase.LOG_REDIS_COMMAND
        and event.get("dst_port") == service.port
        and event.get("logdata", {}).get("CMD") == command,
    )


def test_redis_requires_authentication(canary):
    service = canary("redis")
    start = service.get_log_count()
    with get_redis_client(service) as client:
        with pytest.raises(redis.exceptions.AuthenticationError):
            client.ping()

    log = get_redis_log(service, start, "PING")
    assert log is not None
    assert log["logdata"]["CMD"] == "PING"


def test_redis_auth_attempt_is_logged(canary):
    service = canary("redis")
    start = service.get_log_count()
    with get_redis_client(service, password="test_pass") as client:
        with pytest.raises(redis.exceptions.AuthenticationError):
            client.ping()

    log = get_redis_log(service, start, "AUTH")
    assert log is not None
    assert "test_pass" in log["logdata"]["ARGS"]


def test_redis_unknown_command_is_logged(canary):
    service = canary("redis")
    start = service.get_log_count()
    with get_redis_client(service) as client:
        with pytest.raises(redis.exceptions.ResponseError):
            client.execute_command("CANARY_UNKNOWN")

    log = get_redis_log(service, start, "CANARY_UNKNOWN")
    assert log is not None
    assert log["logdata"]["CMD"] == "CANARY_UNKNOWN"
