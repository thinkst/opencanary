import pytest
import paramiko


@pytest.fixture
def ssh_connection():
    connection = paramiko.SSHClient()
    connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    yield connection
    connection.close()


def test_ssh_with_basic_login(ssh_connection, canary):
    """
    Try to log into the SSH server
    """
    server = canary("ssh")
    start = server.get_log_count()
    with pytest.raises(paramiko.ssh_exception.AuthenticationException):
        ssh_connection.connect(
            hostname=server.host,
            port=server.port,
            username="test_user",
            password="test_pass",
            timeout=5,
            banner_timeout=5,
            auth_timeout=5,
            allow_agent=False,
            look_for_keys=False,
        )
    last_log = server.get_matching_log(
        start,
        lambda entry: entry.get("logdata", {}).get("USERNAME") == "test_user",
    )
    assert last_log is not None
    assert last_log["dst_port"] == server.port
    assert "paramiko" in last_log["logdata"]["REMOTEVERSION"]
    assert last_log["logdata"]["USERNAME"] == "test_user"
    assert last_log["logdata"]["PASSWORD"] == "test_pass"
