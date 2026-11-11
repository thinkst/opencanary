import socket

from opencanary.logger import LoggerBase


def get_tcpbanner_log(server, start_line):
    def is_matching_log(log):
        if log.get("logtype") != LoggerBase.LOG_TCP_BANNER_DATA_RECEIVED:
            return False
        if log.get("dst_port") != server.port:
            return False
        if log.get("logdata", {}).get("FUNCTION") != "DATA_RECEIVED":
            return False
        if log.get("logdata", {}).get("BANNER_ID") != "1":
            return False
        return True

    return server.get_matching_log(start_line, is_matching_log)


def test_tcpbanner_alert_and_response(canary):
    """
    Send alert text to tcpbanner service and verify logging and response.
    """
    server = canary("tcpbanner")
    log_start = server.get_log_count()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect((server.host, server.port))

        init_banner = connection.recv(1024)
        assert b"OpenCanary TCPBanner" in init_banner

        connection.sendall(b"hello ALERT from test\r\n")
        response_banner = connection.recv(1024)
        assert response_banner == b"OK\r\n"

    log = get_tcpbanner_log(server, log_start)
    assert log is not None
    assert log["dst_port"] == server.port
    assert log["logtype"] == LoggerBase.LOG_TCP_BANNER_DATA_RECEIVED
    assert log["logdata"]["FUNCTION"] == "DATA_RECEIVED"
    assert "ALERT" in log["logdata"]["ALERT_STRING"]
