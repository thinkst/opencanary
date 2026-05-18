import socket

from helpers import get_log_count, get_matching_log
from opencanary.logger import LoggerBase

VNC_PORT = 5000
VNC_VERSION = b"RFB 003.008\n"


def get_vnc_log(start_line):
    def is_matching_log(log):
        if log.get("logtype") != LoggerBase.LOG_VNC:
            return False
        if log.get("dst_port") != VNC_PORT:
            return False
        if "VNC Server Challenge" not in log.get("logdata", {}):
            return False
        if "VNC Client Response" not in log.get("logdata", {}):
            return False
        return True

    return get_matching_log(start_line, is_matching_log)


def test_vnc_auth_attempt_is_logged():
    """
    Perform a minimal VNC handshake and send auth response.
    """
    log_start = get_log_count()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(("localhost", VNC_PORT))

        server_hello = connection.recv(12)
        assert server_hello == VNC_VERSION

        connection.sendall(VNC_VERSION)
        security_types = connection.recv(2)
        assert security_types == b"\x01\x02"

        connection.sendall(b"\x02")
        challenge = connection.recv(16)
        assert len(challenge) == 16

        connection.sendall(b"\x00" * 16)

    log = get_vnc_log(log_start)
    assert log is not None
    assert log["dst_port"] == VNC_PORT
    assert log["logtype"] == LoggerBase.LOG_VNC
    assert len(log["logdata"]["VNC Server Challenge"]) == 32
    assert len(log["logdata"]["VNC Client Response"]) == 32
