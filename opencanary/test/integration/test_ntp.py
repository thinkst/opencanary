import socket


def test_ntp_server_monlist(canary):
    """Check that the MON_GETLIST_1 NTP command was logged correctly."""
    server = canary("ntp")
    start = server.get_log_count()
    packet = (
        b"\x17"
        + b"\x00"  # response more version mode
        + b"\x03"  # sequence number
        + b"\x2a"  # implementation (NTPv3)
        + b"\x00"  # request (MON_GETLIST_1)
        + b"\x00"  # error number / number of data items
        + b"\x00"  # item_size  # data
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(packet, (server.host, server.port))

    last_log = server.get_matching_log(
        start,
        lambda entry: entry.get("logdata", {}).get("NTP CMD") == "monlist",
    )
    assert last_log is not None
    assert last_log["logdata"]["NTP CMD"] == "monlist"
    assert last_log["dst_port"] == server.port
