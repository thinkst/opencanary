import socket

from helpers import get_log_count, get_matching_log
from opencanary.logger import LoggerBase

TFTP_PORT = 69


def get_tftp_log(start_line):
    def is_matching_log(log):
        if log.get("logtype") != LoggerBase.LOG_TFTP:
            return False
        if log.get("dst_port") != TFTP_PORT:
            return False
        if log.get("logdata", {}).get("OPCODE") != "READ":
            return False
        return True

    return get_matching_log(start_line, is_matching_log)


def test_tftp_read_request_is_logged():
    """
    Send a TFTP RRQ packet and verify it is logged.
    """
    log_start = get_log_count()
    packet = b"\x00\x01canary.txt\x00octet\x00"

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.sendto(packet, ("localhost", TFTP_PORT))

    log = get_tftp_log(log_start)
    assert log is not None
    assert log["dst_port"] == TFTP_PORT
    assert log["logtype"] == LoggerBase.LOG_TFTP
    assert log["logdata"]["FILENAME"] == "canary.txt"
    assert log["logdata"]["MODE"] == "octet"
