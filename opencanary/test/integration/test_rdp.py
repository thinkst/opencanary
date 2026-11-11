import pytest
import socket


@pytest.fixture
def rdp_connection(canary):
    server = canary("rdp")
    start = server.get_log_count()
    connection = socket.create_connection((server.host, server.port), timeout=5)
    yield connection, server, start
    connection.close()


def test_rdp_with_user_cookie(rdp_connection):
    """
    Login to the RDP server and pass the username in the connection request
    """
    rdp_connection, server, start = rdp_connection
    packet = b""
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3
    # TPKT details
    packet += b"\x03\x00\x00\x33"
    # ISO connection
    packet += b"\x2e\xe0\x00\x00\x00\x00\x00"
    # RDP Cookie
    packet += b"Cookie: mstshash=test_rdp_user"
    # Negotiation request
    packet += b"\x01\x00\x08\x00\x03\x00\x00\x00"
    rdp_connection.sendall(packet)

    last_log = server.get_matching_log(
        start,
        lambda entry: entry.get("logdata", {}).get("USERNAME") == "test_rdp_user",
    )
    assert last_log is not None
    assert last_log["logdata"]["USERNAME"] == "test_rdp_user"
    assert last_log["dst_port"] == server.port


def test_rdp_connection_with_no_user_details(rdp_connection):
    """
    Connect to the RDP server, but do not pass a username (e.g. nmap scan)
    """
    rdp_connection, server, start = rdp_connection
    packet = b""
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3
    # TPKT details
    packet += b"\x03\x00\x00\x13"
    # ISO connection
    packet += b"\x0e\xe0\x00\x00\x00\x00\x01"
    # Negotiation request
    packet += b"\x01\x00\x08\x00\x03\x00\x00\x00"
    rdp_connection.sendall(packet)

    last_log = server.get_matching_log(
        start,
        lambda entry: (
            "USERNAME" in entry.get("logdata", {})
            and entry["logdata"]["USERNAME"] is None
        ),
    )
    assert last_log is not None
    assert last_log["logdata"]["USERNAME"] is None
    assert last_log["dst_port"] == server.port
