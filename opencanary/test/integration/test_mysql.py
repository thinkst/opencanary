import pytest
import pymysql


def test_mysql_server_login(canary):
    """
    Login to the mysql server
    """
    server = canary("mysql")
    start = server.get_log_count()
    with pytest.raises(pymysql.err.OperationalError):
        pymysql.connect(
            host=server.host,
            port=server.port,
            connect_timeout=5,
            read_timeout=5,
            write_timeout=5,
            user="test_user",
            password="test_pass",
            database="db",
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
        )
    last_log = server.get_matching_log(
        start,
        lambda entry: entry.get("logdata", {}).get("USERNAME") == "test_user",
    )
    assert last_log is not None
    assert last_log["logdata"]["USERNAME"] == "test_user"
    assert last_log["dst_port"] == server.port


def test_attempted_mysql_login(canary):
    """
    Trying to connect to the mysql service should log the connection attempt.
    """
    server = canary("mysql")
    start = server.get_log_count()
    with pytest.raises(pymysql.err.OperationalError):
        pymysql.connect(
            host=server.host,
            port=server.port,
            connect_timeout=5,
            read_timeout=5,
            write_timeout=5,
            user="anyone",
            password="AsDAS9d103294",
            database="invaliddb",
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
        )
    log = server.get_matching_log(start, lambda entry: entry.get("logtype") == 9003)
    assert log is not None
    assert log["logtype"] == 9003
    assert log["dst_port"] == server.port
    assert log["logdata"] == {}
