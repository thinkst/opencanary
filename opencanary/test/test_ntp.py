import pytest
import socket
import time

from helpers import get_last_log


@pytest.fixture
def send_ntp_request():
    packet = (
        b"\x17"
        + b"\x00"  # response more version mode
        + b"\x03"  # sequence number
        + b"\x2a"  # implementation (NTPv3)
        + b"\x00"  # request (MON_GETLIST_1)
        + b"\x00"  # error number / number of data items
        + b"\x00"  # item_size  # data
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet, ("localhost", 123))
    yield
    sock.close()


def test_ntp_server_monlist(send_ntp_request):
    """
    Check that the MON_GETLIST_1 NTP command was logged correctly
    """
    # The logs take about a second to show up, in other tests this is not
    # an issue, because there are checks that run before looking at the log
    # (e.g. request.status_code == 200 for HTTP) but for NTP we just check
    # the log. A hardcoded time out is a horible solution, but it works.
    time.sleep(1)

    last_log = get_last_log()
    assert last_log["logdata"]["NTP CMD"] == "monlist"
    assert last_log["dst_port"] == 123
