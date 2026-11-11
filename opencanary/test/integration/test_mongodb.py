import socket
import struct
import time

import pytest
from pymongo import MongoClient
from pymongo.errors import OperationFailure

MONGODB_VERSION = "4.4.6"
MONGODB_MAX_WIRE_VERSION = 9
MONGODB_AUTH_FAILED_CODE = 18
MONGODB_UNAUTHORIZED_CODE = 13
MONGODB_CLIENT_OPTIONS = {
    "serverSelectionTimeoutMS": 2000,
    "connectTimeoutMS": 2000,
    "socketTimeoutMS": 2000,
    "directConnection": True,
}

# Probe a different service running on the same child reactor.
VNC_VERSION = b"RFB 003.008\n"


def get_mongodb_log(server, action, start_line, logdata=None):
    logdata = logdata or {}

    def is_matching_log(log):
        if log["dst_port"] != server.port:
            return False
        if log["logdata"].get("action") != action:
            return False
        if not all(log["logdata"].get(k) == v for k, v in logdata.items()):
            return False
        return True

    return server.get_matching_log(start_line, is_matching_log)


def reactor_is_answering(server, timeout: float = 1.0) -> bool:
    """Is a different module on the shared reactor still replying?"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(timeout)
            probe.connect((server.host, server.ports["vnc"]))
            return probe.recv(len(VNC_VERSION)) == VNC_VERSION
    except OSError:
        return False


def scram_sasl_message(payload: bytes) -> bytes:
    """One OP_MSG carrying {saslStart: 1, payload: <bytes>}."""
    body = (
        b"\x10saslStart\x00"
        + struct.pack("<i", 1)
        + b"\x05payload\x00"
        + struct.pack("<I", len(payload))
        + b"\x00"
        + payload
        + b"\x00"
    )
    doc = struct.pack("<I", len(body) + 4) + body
    return (
        struct.pack("<IIII", 16 + 5 + len(doc), 1, 0, 2013)
        + struct.pack("<I", 0)
        + b"\x00"
        + doc
    )


@pytest.fixture
def mongodb_server(canary):
    return canary("mongodb")


@pytest.fixture
def log_start(mongodb_server):
    return mongodb_server.get_log_count()


@pytest.fixture
def mongodb_client(mongodb_server, log_start):
    client = MongoClient(
        mongodb_server.host, mongodb_server.port, **MONGODB_CLIENT_OPTIONS
    )
    yield client
    client.close()


def test_mongodb_hello(mongodb_server, mongodb_client, log_start):
    """
    Connect to the MongoDB service and send a hello command.
    """
    response = mongodb_client.admin.command("hello")

    assert response["ok"] == 1.0
    assert response["ismaster"] is True
    assert response["maxWireVersion"] == MONGODB_MAX_WIRE_VERSION
    assert response["version"] == MONGODB_VERSION

    last_log = get_mongodb_log(mongodb_server, "mongodb.connection", log_start)
    assert last_log is not None
    assert last_log["logtype"] == 20001
    assert last_log["dst_port"] == mongodb_server.port
    assert last_log["logdata"]["action"] == "mongodb.connection"


def test_mongodb_auth_attempt(mongodb_server, log_start):
    """
    Try to authenticate to the MongoDB service.
    """
    client = MongoClient(
        f"mongodb://test_user:test_pass@{mongodb_server.host}:{mongodb_server.port}/admin?"
        "authMechanism=SCRAM-SHA-256",
        **MONGODB_CLIENT_OPTIONS,
    )

    try:
        with pytest.raises(OperationFailure) as error:
            client.admin.command("ping")

        assert error.value.code == MONGODB_AUTH_FAILED_CODE
        last_log = get_mongodb_log(
            mongodb_server,
            "mongodb.auth_attempt",
            log_start,
            {"username": "test_user", "mechanism": "SCRAM-SHA-256"},
        )
        assert last_log is not None
        assert last_log["logtype"] == 20001
        assert last_log["dst_port"] == mongodb_server.port
        assert last_log["logdata"]["action"] == "mongodb.auth_attempt"
        assert last_log["logdata"]["username"] == "test_user"
        assert last_log["logdata"]["mechanism"] == "SCRAM-SHA-256"
        assert "payload" in last_log["logdata"]["auth_data"]
    finally:
        client.close()


def test_mongodb_command_attempt(mongodb_server, mongodb_client, log_start):
    """
    Try to run an unauthenticated MongoDB command.
    """
    with pytest.raises(OperationFailure) as error:
        mongodb_client.admin.command("listDatabases")

    assert error.value.code == MONGODB_UNAUTHORIZED_CODE

    last_log = get_mongodb_log(
        mongodb_server, "mongodb.command", log_start, {"command": "listDatabases"}
    )
    assert last_log is not None
    assert last_log["logtype"] == 20001
    assert last_log["dst_port"] == mongodb_server.port
    assert last_log["logdata"]["action"] == "mongodb.command"
    assert last_log["logdata"]["command"] == "listDatabases"
    assert "listDatabases" in last_log["logdata"]["query"]


@pytest.mark.parametrize(
    "payload,expected",
    [
        (b"n,,n=alice,r=nonce123456789", "alice"),
        (b"n=alice,r=nonce123456789", "alice"),
        (b"n,,n=user=2Cname,r=nonce123456789", "user=2Cname"),
    ],
)
def test_mongodb_scram_username_is_extracted_from_both_shapes(
    mongodb_server, log_start, payload, expected
):
    """The username is read whether or not the payload carries a gs2-header.

    `n=([^,]{1,256}),` matches the legal SCRAM username field (RFC 5802: a comma can only
    appear in a username escaped as `=2C`), so a conformant client's `n,,n=user,r=...` and a
    bare `n=user,r=...` both yield the username. Anchoring the pattern on a leading comma
    instead would have logged `unknown` for the bare shape.
    """
    with socket.create_connection(
        (mongodb_server.host, mongodb_server.port), timeout=5
    ) as connection:
        connection.sendall(scram_sasl_message(payload))
        connection.recv(4096)

    last_log = get_mongodb_log(
        mongodb_server, "mongodb.auth_attempt", log_start, {"username": expected}
    )
    assert last_log is not None, f"{payload!r} must log {expected!r}"


def test_mongodb_scram_payload_does_not_freeze_the_reactor(canary):
    """A payload shaped to make `n=(.+?),` backtrack must not stall the shared reactor.

    120KB of `n=` with no comma took ~26s and froze every other module while the reactor sat
    in the regex; the daemon has to answer a *different* service while this is in flight.
    """
    server = canary("mongodb", "vnc")
    log_start = server.get_log_count()
    assert reactor_is_answering(server), "the vnc decoy is not answering"

    with socket.create_connection((server.host, server.port), timeout=5) as connection:
        connection.sendall(scram_sasl_message(b"n=" * 60_000))
        started = time.monotonic()
        try:
            connection.recv(4096)
        except socket.timeout:
            pytest.fail("mongodb stopped answering: the reactor is busy in the regex")
        assert (
            time.monotonic() - started < 2
        ), "the match must not scale with the payload"

    assert reactor_is_answering(
        server
    ), "another honeypot service was starved by the regex"

    last_log = get_mongodb_log(server, "mongodb.auth_attempt", log_start)
    assert last_log is not None
