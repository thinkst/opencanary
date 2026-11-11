import pytest
from ftplib import FTP, error_perm

from opencanary.logger import LoggerBase


@pytest.fixture
def ftp_client(canary):
    server = canary("ftp")
    start = server.get_log_count()
    ftp = FTP(timeout=5)
    ftp.connect(server.host, server.port)
    yield ftp, server, start
    ftp.close()


def test_attempted_ftp_connection(ftp_client):
    """
    Try to connect to the FTP service should log the connection attempt.
    """
    ftp_client, server, start = ftp_client
    with pytest.raises(error_perm):
        ftp_client.login()
    log = server.get_matching_log(start, lambda entry: entry.get("logtype") == 2001)
    assert log is not None
    assert log["logtype"] == 2001
    assert log["dst_port"] == server.port
    assert log["logdata"] == {}


def test_anonymous_ftp(ftp_client):
    """
    Try to connect to the FTP service with no username or password.
    """
    ftp_client, server, start = ftp_client
    with pytest.raises(error_perm):
        ftp_client.login()
    log = server.get_matching_log(
        start,
        lambda entry: entry.get("logdata", {}).get("USERNAME") == "anonymous",
    )
    assert log is not None
    assert log["dst_port"] == server.port
    assert log["logdata"]["USERNAME"] == "anonymous"
    assert log["logdata"]["PASSWORD"] == "anonymous@"


def test_authenticated_ftp(ftp_client):
    """
    Connect to the FTP service with a test username and password.
    """
    ftp_client, server, start = ftp_client
    with pytest.raises(error_perm):
        ftp_client.login(user="test_user", passwd="test_pass")
    last_log = server.get_matching_log(
        start,
        lambda entry: entry.get("logdata", {}).get("USERNAME") == "test_user",
    )
    assert last_log is not None
    assert last_log["dst_port"] == server.port
    assert last_log["logdata"]["USERNAME"] == "test_user"
    assert last_log["logdata"]["PASSWORD"] == "test_pass"


@pytest.mark.parametrize(
    "username,expected",
    [("ftp_honeycred_test", True), ("ftp_other_user", False)],
)
def test_ftp_honeycred_detection(ftp_client, username, expected):
    ftp_client, server, start = ftp_client

    with pytest.raises(error_perm):
        ftp_client.login(user=username, passwd="arbitrary_password")

    event = server.get_matching_log(
        start,
        lambda entry: (
            entry.get("logtype") == LoggerBase.LOG_FTP_LOGIN_ATTEMPT
            and entry.get("dst_port") == server.port
            and entry.get("logdata", {}).get("USERNAME") == username
        ),
    )
    assert event is not None
    assert event["logdata"]["PASSWORD"] == "arbitrary_password"
    assert event["honeycred"] is expected
