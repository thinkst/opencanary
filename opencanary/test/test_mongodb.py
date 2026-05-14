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
