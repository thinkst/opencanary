import pytest
import paramiko


@pytest.fixture
def ssh_connection():
    connection = paramiko.SSHClient()
    connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    yield connection
    connection.close()


@pytest.mark.parametrize(
    "kex",
    [
        pytest.param(None, id="default"),
        "diffie-hellman-group-exchange-sha256",
    ],
)
def test_ssh_with_basic_login(ssh_connection, canary, kex):
    """
    Try to log into the SSH server
    """

    def transport_factory(*args, **kwargs):
        transport = paramiko.Transport(*args, **kwargs)
        if kex is not None:
            transport.get_security_options().kex = (kex,)
        return transport

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
            transport_factory=transport_factory,
        )
    last_log = server.get_matching_log(
        start,
        lambda entry: (
            entry.get("logtype") == 4002
            and entry.get("logdata", {}).get("USERNAME") == "test_user"
        ),
    )
    assert last_log["dst_port"] == server.port
    assert (
        last_log["logdata"]["REMOTEVERSION"]
        == ssh_connection.get_transport().local_version
    )
    assert last_log["logdata"]["USERNAME"] == "test_user"
    assert last_log["logdata"]["PASSWORD"] == "test_pass"
