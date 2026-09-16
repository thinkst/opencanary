import pytest
from ftplib import FTP, error_perm

from helpers import get_last_log, get_last_n_logs, get_log_count, get_matching_log
from opencanary.logger import LoggerBase


@pytest.fixture
def ftp_client():
    ftp = FTP("localhost")
    yield ftp
    ftp.close()


def test_attempted_ftp_connection(ftp_client):
    """
    Try to connect to the FTP service should log the connection attempt.
    """
    with pytest.raises(error_perm):
        ftp_client.login()
    log = get_last_n_logs(2)[0]
    assert log["logtype"] == 2001
    assert log["dst_port"] == 21
    assert log["logdata"] == {}


def test_anonymous_ftp(ftp_client):
    """
    Try to connect to the FTP service with no username or password.
    """
    with pytest.raises(error_perm):
        ftp_client.login()
    log = get_last_log()
    assert log["dst_port"] == 21
    assert log["logdata"]["USERNAME"] == "anonymous"
    assert log["logdata"]["PASSWORD"] == "anonymous@"


def test_authenticated_ftp(ftp_client):
    """
    Connect to the FTP service with a test username and password.
    """
    with pytest.raises(error_perm):
        ftp_client.login(user="test_user", passwd="test_pass")
    last_log = get_last_log()
    assert last_log["dst_port"] == 21
    assert last_log["logdata"]["USERNAME"] == "test_user"
    assert last_log["logdata"]["PASSWORD"] == "test_pass"


@pytest.mark.parametrize(
    "username,expected",
    [("ftp_honeycred_test", True), ("ftp_other_user", False)],
)
def test_ftp_honeycred_detection(ftp_client, username, expected):
    start = get_log_count()

    with pytest.raises(error_perm):
        ftp_client.login(user=username, passwd="arbitrary_password")

    event = get_matching_log(
        start,
        lambda entry: (
            entry.get("logtype") == LoggerBase.LOG_FTP_LOGIN_ATTEMPT
            and entry.get("dst_port") == 21
            and entry.get("logdata", {}).get("USERNAME") == username
        ),
    )
    assert event is not None
    assert event["logdata"]["PASSWORD"] == "arbitrary_password"
    assert event["honeycred"] is expected
