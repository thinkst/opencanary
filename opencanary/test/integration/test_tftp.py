import socket

from opencanary.logger import LoggerBase


def get_tftp_log(server, start_line):
    def is_matching_log(log):
        if log.get("logtype") != LoggerBase.LOG_TFTP:
            return False
        if log.get("dst_port") != server.port:
            return False
        if log.get("logdata", {}).get("OPCODE") != "READ":
            return False
        return True

    return server.get_matching_log(start_line, is_matching_log)


def test_tftp_read_request_is_logged(canary):
    """
    Send a TFTP RRQ packet and verify it is logged.
    """
    server = canary("tftp")
    log_start = server.get_log_count()
    packet = b"\x00\x01canary.txt\x00octet\x00"

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(5)
        connection.sendto(packet, (server.host, server.port))

    log = get_tftp_log(server, log_start)
    assert log is not None
    assert log["dst_port"] == server.port
    assert log["logtype"] == LoggerBase.LOG_TFTP
    assert log["logdata"]["FILENAME"] == "canary.txt"
    assert log["logdata"]["MODE"] == "octet"
