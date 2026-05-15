import socket

from helpers import get_log_count, get_matching_log
from opencanary.logger import LoggerBase

TCPBANNER_PORT = 8001


def get_tcpbanner_log(start_line):
    def is_matching_log(log):
        if log.get("logtype") != LoggerBase.LOG_TCP_BANNER_DATA_RECEIVED:
            return False
        if log.get("dst_port") != TCPBANNER_PORT:
            return False
        if log.get("logdata", {}).get("FUNCTION") != "DATA_RECEIVED":
            return False
        if log.get("logdata", {}).get("BANNER_ID") != "1":
            return False
        return True

    return get_matching_log(start_line, is_matching_log)


def test_tcpbanner_alert_and_response():
    """
    Send alert text to tcpbanner service and verify logging and response.
    """
    log_start = get_log_count()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(("localhost", TCPBANNER_PORT))

        init_banner = connection.recv(1024)
        assert b"OpenCanary TCPBanner" in init_banner

        connection.sendall(b"hello ALERT from test\r\n")
        response_banner = connection.recv(1024)
        assert response_banner == b"OK\r\n"

    log = get_tcpbanner_log(log_start)
    assert log is not None
    assert log["dst_port"] == TCPBANNER_PORT
    assert log["logtype"] == LoggerBase.LOG_TCP_BANNER_DATA_RECEIVED
    assert log["logdata"]["FUNCTION"] == "DATA_RECEIVED"
    assert "ALERT" in log["logdata"]["ALERT_STRING"]
