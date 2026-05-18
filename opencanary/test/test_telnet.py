import socket
import time

from helpers import get_log_count, get_matching_log
from opencanary.logger import LoggerBase

TELNET_PORT = 23


def get_telnet_log(start_line, logtype):
    def is_matching_log(log):
        return log.get("logtype") == logtype and log.get("dst_port") == TELNET_PORT

    return get_matching_log(start_line, is_matching_log)


def test_telnet_connection_and_login_attempt_are_logged():
    """
    Connect and submit credentials to telnet service.
    """
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
