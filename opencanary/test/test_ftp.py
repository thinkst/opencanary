import pytest
from ftplib import FTP, error_perm

from helpers import get_last_log, get_last_n_logs


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
