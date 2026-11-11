import socket

from opencanary.logger import LoggerBase


def get_sip_log(server, start_line):
    def is_matching_log(log):
        if log.get("logtype") != LoggerBase.LOG_SIP_REQUEST:
            return False
        if log.get("dst_port") != server.port:
            return False
        if "HEADERS" not in log.get("logdata", {}):
            return False
        return True

    return server.get_matching_log(start_line, is_matching_log)


def test_sip_request_is_logged(canary):
    """
    Send a SIP OPTIONS request over UDP and verify it is logged.
    """
    server = canary("sip")
    log_start = server.get_log_count()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(5)
        connection.bind((server.host, 0))
        client_port = connection.getsockname()[1]
        request = (
            f"OPTIONS sip:test@{server.host}:{server.port} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {server.host}:{client_port};branch=z9hG4bK-524287-1---abcdef\r\n"
            "Max-Forwards: 70\r\n"
            "From: <sip:caller@localhost>;tag=12345\r\n"
            "To: <sip:test@localhost>\r\n"
            "Call-ID: abcdef123456@localhost\r\n"
            "CSeq: 1 OPTIONS\r\n"
            f"Contact: <sip:caller@{server.host}:{client_port}>\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        ).encode("utf-8")
        connection.sendto(request, (server.host, server.port))

    log = get_sip_log(server, log_start)
    assert log is not None
    assert log["dst_port"] == server.port
    assert log["logtype"] == LoggerBase.LOG_SIP_REQUEST
    assert log["logdata"]["HEADERS"] != {}
