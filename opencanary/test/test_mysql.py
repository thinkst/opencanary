import pytest
import pymysql

from helpers import get_last_log, get_last_n_logs


def test_mysql_server_login():
    """
    Login to the mysql server
    """
    with pytest.raises(pymysql.err.OperationalError):
        pymysql.connect(
            host="localhost",
            user="test_user",
            password="test_pass",
            database="db",
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
        )
    last_log = get_last_log()
    assert last_log["logdata"]["USERNAME"] == "test_user"
    assert last_log["dst_port"] == 3306


def test_attempted_mysql_login():
    """
    Trying to connect to the mysql service should log the connection attempt.
    """
    with pytest.raises(pymysql.err.OperationalError):
        pymysql.connect(
            host="localhost",
            user="anyone",
            password="AsDAS9d103294",
            database="invaliddb",
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
        )
    log = get_last_n_logs(2)[0]
    assert log["logtype"] == 9003
    assert log["dst_port"] == 3306
    assert log["logdata"] == {}
