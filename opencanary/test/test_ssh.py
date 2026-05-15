import pytest
import paramiko

from helpers import get_last_log


@pytest.fixture
def ssh_connection():
    connection = paramiko.SSHClient()
    connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    yield connection
    connection.close()


def test_ssh_with_basic_login(ssh_connection):
    """
    Try to log into the SSH server
    """
    with pytest.raises(paramiko.ssh_exception.AuthenticationException):
        ssh_connection.connect(
            hostname="localhost", port=2222, username="test_user", password="test_pass"
        )
    last_log = get_last_log()
    assert last_log["dst_port"] == 2222
    assert "paramiko" in last_log["logdata"]["REMOTEVERSION"]
    assert last_log["logdata"]["USERNAME"] == "test_user"
    assert last_log["logdata"]["PASSWORD"] == "test_pass"
