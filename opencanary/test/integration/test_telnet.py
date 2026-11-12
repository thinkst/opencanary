import socket
import time

from opencanary.logger import LoggerBase


def receive_until(connection, marker):
    deadline = time.monotonic() + 5
    received = bytearray()
    while marker not in received:
        remaining = deadline - time.monotonic()
        assert remaining > 0, f"Timed out waiting for {marker!r}: {received!r}"
        connection.settimeout(remaining)
        chunk = connection.recv(4096)
        assert chunk, f"Connection closed before {marker!r}: {received!r}"
        received.extend(chunk)


def test_telnet_connection_and_login_attempt_are_logged(canary):
    service = canary("telnet")
    start = service.get_log_count()
    with socket.create_connection(
        (service.host, service.port), timeout=5
    ) as connection:
        receive_until(connection, b"Username: ")
        connection.sendall(b"test_user\r\n")
        receive_until(connection, b"Password: ")
        connection.sendall(b"test_pass\r\n")

        login_log = service.get_matching_log(
            start,
            lambda event: event.get("logtype") == LoggerBase.LOG_TELNET_LOGIN_ATTEMPT
            and event.get("dst_port") == service.port,
        )
        assert login_log is not None
        assert login_log["logdata"]["USERNAME"] == "test_user"
        assert login_log["logdata"]["PASSWORD"] == "test_pass"

    connection_log = service.get_matching_log(
        start,
        lambda event: event.get("logtype") == LoggerBase.LOG_TELNET_CONNECTION_MADE
        and event.get("dst_port") == service.port,
    )
    assert connection_log is not None
