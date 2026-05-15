import socket

from helpers import get_log_count, get_matching_log
from opencanary.logger import LoggerBase

SIP_PORT = 5060


def get_sip_log(start_line):
    def is_matching_log(log):
        if log.get("logtype") != LoggerBase.LOG_SIP_REQUEST:
            return False
        if log.get("dst_port") != SIP_PORT:
            return False
        if "HEADERS" not in log.get("logdata", {}):
            return False
        return True

    return get_matching_log(start_line, is_matching_log)


def test_sip_request_is_logged():
    """
    Send a SIP OPTIONS request over UDP and verify it is logged.
    """
    log_start = get_log_count()
    request = (
        "OPTIONS sip:test@localhost SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-524287-1---abcdef\r\n"
        "Max-Forwards: 70\r\n"
        "From: <sip:caller@localhost>;tag=12345\r\n"
        "To: <sip:test@localhost>\r\n"
        "Call-ID: abcdef123456@localhost\r\n"
        "CSeq: 1 OPTIONS\r\n"
        "Contact: <sip:caller@127.0.0.1:5061>\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    ).encode("utf-8")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.sendto(request, ("localhost", SIP_PORT))

    log = get_sip_log(log_start)
    assert log is not None
    assert log["dst_port"] == SIP_PORT
    assert log["logtype"] == LoggerBase.LOG_SIP_REQUEST
    assert log["logdata"]["HEADERS"] != {}
