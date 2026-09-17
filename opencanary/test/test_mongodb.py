import socket
import struct
import time

import pytest
from pymongo import MongoClient
from pymongo.errors import OperationFailure

from helpers import get_log_count, get_matching_log

MONGODB_PORT = 27017
MONGODB_VERSION = "4.4.6"
MONGODB_AUTH_FAILED_CODE = 18
MONGODB_UNAUTHORIZED_CODE = 13
MONGODB_CLIENT_OPTIONS = {
    "serverSelectionTimeoutMS": 2000,
    "connectTimeoutMS": 2000,
    "socketTimeoutMS": 2000,
    "directConnection": True,
}

# The liveness probe for "is the shared reactor still answering" - a different module, enabled
# in opencanary/test/opencanary.conf, that replies on connect. Probing a module the test config
# disables (mssql, :1433) raises ConnectionRefusedError and reads as a freeze that is really a
# missing listener.
VNC_PORT = 5000
VNC_VERSION = b"RFB 003.008\n"


def get_mongodb_client(uri="mongodb://localhost:27017"):
    return MongoClient(uri, **MONGODB_CLIENT_OPTIONS)


def get_mongodb_log(action, start_line, logdata=None):
    logdata = logdata or {}

    def is_matching_log(log):
        if log["dst_port"] != MONGODB_PORT:
            return False
        if log["logdata"].get("action") != action:
            return False
        if not all(log["logdata"].get(k) == v for k, v in logdata.items()):
            return False
        return True

    return get_matching_log(start_line, is_matching_log)


def reactor_is_answering(timeout: float = 1.0) -> bool:
    """Is a different module on the shared reactor still replying?"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(timeout)
            probe.connect(("localhost", VNC_PORT))
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
def log_start():
    return get_log_count()


@pytest.fixture
def mongodb_client():
    client = get_mongodb_client()
    yield client
    client.close()


def test_mongodb_hello(mongodb_client, log_start):
    """
    Connect to the MongoDB service and send a hello command.
    """
    response = mongodb_client.admin.command("hello")

    assert response["ok"] == 1.0
    assert response["ismaster"] is True
    assert response["version"] == MONGODB_VERSION

    last_log = get_mongodb_log("mongodb.connection", log_start)
    assert last_log is not None
    assert last_log["logtype"] == 20001
    assert last_log["dst_port"] == MONGODB_PORT
    assert last_log["logdata"]["action"] == "mongodb.connection"


def test_mongodb_auth_attempt(log_start):
    """
    Try to authenticate to the MongoDB service.
    """
    client = get_mongodb_client(
        "mongodb://test_user:test_pass@localhost:27017/admin?"
        "authMechanism=SCRAM-SHA-256"
    )

    try:
        with pytest.raises(OperationFailure) as error:
            client.admin.command("ping")

        assert error.value.code == MONGODB_AUTH_FAILED_CODE
        last_log = get_mongodb_log(
            "mongodb.auth_attempt",
            log_start,
            {"username": "test_user", "mechanism": "SCRAM-SHA-256"},
        )
        assert last_log is not None
        assert last_log["logtype"] == 20001
        assert last_log["dst_port"] == MONGODB_PORT
        assert last_log["logdata"]["action"] == "mongodb.auth_attempt"
        assert last_log["logdata"]["username"] == "test_user"
        assert last_log["logdata"]["mechanism"] == "SCRAM-SHA-256"
        assert "payload" in last_log["logdata"]["auth_data"]
    finally:
        client.close()


def test_mongodb_command_attempt(mongodb_client, log_start):
    """
    Try to run an unauthenticated MongoDB command.
    """
    with pytest.raises(OperationFailure) as error:
        mongodb_client.admin.command("listDatabases")

    assert error.value.code == MONGODB_UNAUTHORIZED_CODE

    last_log = get_mongodb_log(
        "mongodb.command", log_start, {"command": "listDatabases"}
    )
    assert last_log is not None
    assert last_log["logtype"] == 20001
    assert last_log["dst_port"] == MONGODB_PORT
    assert last_log["logdata"]["action"] == "mongodb.command"
    assert last_log["logdata"]["command"] == "listDatabases"
    assert "listDatabases" in last_log["logdata"]["query"]


def test_mongodb_scram_username_is_extracted_from_both_shapes(log_start):
    """The username is read whether or not the payload carries a gs2-header.

    `n=([^,]{1,256}),` matches the legal SCRAM username field (RFC 5802: a comma can only
    appear in a username escaped as `=2C`), so a conformant client's `n,,n=user,r=...` and a
    bare `n=user,r=...` both yield the username. Anchoring the pattern on a leading comma
    instead would have logged `unknown` for the bare shape.
    """
    for payload, expected in (
        (b"n,,n=alice,r=nonce123456789", "alice"),
        (b"n=alice,r=nonce123456789", "alice"),
        (b"n,,n=user=2Cname,r=nonce123456789", "user=2Cname"),
    ):
        s = socket.create_connection(("localhost", MONGODB_PORT), timeout=5)
        s.settimeout(5)
        s.sendall(scram_sasl_message(payload))
        s.recv(4096)
        s.close()

        last_log = get_mongodb_log(
            "mongodb.auth_attempt", log_start, {"username": expected}
        )
        assert last_log is not None, f"{payload!r} must log {expected!r}"


def test_mongodb_scram_payload_does_not_freeze_the_reactor(log_start):
    """A payload shaped to make `n=(.+?),` backtrack must not stall the shared reactor.

    120KB of `n=` with no comma took ~26s and froze every other module while the reactor sat
    in the regex; the daemon has to answer a *different* service while this is in flight.
    """
    # Prove the other decoy is up *first*: a module the test config does not enable would
    # otherwise read as "the reactor is frozen" instead of "this test cannot run".
    assert (
        reactor_is_answering()
    ), "the vnc decoy is not up: is the test daemon running?"

    s = socket.create_connection(("localhost", MONGODB_PORT), timeout=5)
    s.settimeout(5)
    s.sendall(scram_sasl_message(b"n=" * 60_000))
    started = time.monotonic()
    try:
        s.recv(4096)
    except socket.timeout:
        pytest.fail("mongodb stopped answering: the reactor is busy in the regex")
    assert time.monotonic() - started < 2, "the match must not scale with the payload"
    s.close()

    assert reactor_is_answering(), "another honeypot service was starved by the regex"

    last_log = get_mongodb_log("mongodb.auth_attempt", log_start)
    assert last_log is not None
