from pathlib import Path
import threading

import pytest
from impacket import smb3structs as smb2
from impacket.nt_errors import STATUS_LOGON_FAILURE, STATUS_MORE_PROCESSING_REQUIRED

from opencanary.config import ConfigException
from opencanary.logger import LoggerBase
from opencanary.modules.samba import (
    AUTH_MODE_GUEST,
    AUTH_MODE_NTLM,
    DEFAULT_SERVER_NAME,
    DEFAULT_SHARE_NAME,
    DEFAULT_SMB_PORT,
    CanarySamba,
    ImpacketSMBService,
)


class FakeConfig:
    def __init__(self, values):
        self.values = values

    def getVal(self, key, default=None):
        try:
            return self.values[key]
        except KeyError:
            if default is not None:
                return default
            raise


class DummyLogger(LoggerBase):
    def __init__(self):
        self.events = []

    def log(self, data):
        self.events.append(data)


class FakeSMBServer:
    def __init__(self, conn_data):
        self.conn_data = conn_data

    def getConnectionData(self, conn_id, checkStatus=True):
        return self.conn_data

    def setConnectionData(self, conn_id, data):
        self.conn_data = data


class FakeAliveThread:
    def __init__(self):
        self.join_timeout = None

    def is_alive(self):
        return True

    def join(self, timeout=None):
        self.join_timeout = timeout


class FakeBlockingTCPServer:
    def __init__(self):
        self.shutdown_started = threading.Event()
        self.release_shutdown = threading.Event()

    def shutdown(self):
        self.shutdown_started.set()
        self.release_shutdown.wait()


class FakeImpacketServer:
    def __init__(self):
        self.tcp_server = FakeBlockingTCPServer()
        self.stopped = False

    def getServer(self):
        return self.tcp_server

    def stop(self):
        self.stopped = True


def make_canary(tmp_path, **overrides):
    share_path = tmp_path / "share"
    share_path.mkdir(exist_ok=True)
    config = {
        "device.node_id": "test-node",
        "device.listen_addr": "127.0.0.1",
        "smb.port": 0,
        "smb.share_path": str(share_path),
    }
    config.update(overrides)
    logger = DummyLogger()
    return CanarySamba(config=FakeConfig(config), logger=logger), logger


def test_smb_defaults_use_packaged_read_only_share():
    logger = DummyLogger()
    canary = CanarySamba(
        config=FakeConfig({"device.node_id": "test-node"}), logger=logger
    )

    assert canary.port == DEFAULT_SMB_PORT
    assert canary.share_name == DEFAULT_SHARE_NAME
    assert canary.server_name == DEFAULT_SERVER_NAME
    assert Path(canary.share_path).is_dir()


def test_get_service_rejects_missing_share_path(tmp_path):
    missing_path = tmp_path / "missing"
    canary, _logger = make_canary(tmp_path, **{"smb.share_path": str(missing_path)})

    with pytest.raises(ConfigException) as exc_info:
        canary.getService()

    assert exc_info.value.key == "smb.share_path"


def test_smb_defaults_to_guest_auth_mode():
    logger = DummyLogger()
    canary = CanarySamba(
        config=FakeConfig({"device.node_id": "test-node"}), logger=logger
    )

    assert canary.auth_mode == AUTH_MODE_GUEST


def test_ntlm_auth_mode_requires_credentials(tmp_path):
    with pytest.raises(ConfigException) as exc_info:
        make_canary(tmp_path, **{"smb.auth_mode": AUTH_MODE_NTLM})

    assert exc_info.value.key == "smb.ntlm_username"


def test_ntlm_auth_config_registers_credentials_and_disables_guest(tmp_path):
    canary, _logger = make_canary(
        tmp_path,
        **{
            "smb.auth_mode": AUTH_MODE_NTLM,
            "smb.ntlm_username": "alice",
            "smb.ntlm_password": "secret",
        }
    )
    server = canary._build_server()
    try:
        server_config = server.getServer().getServerConfig()
        credentials = server.getServer().getCredentials()

        assert server_config.getboolean("global", "anonymous_logon") is False
        assert credentials["alice"][0] == canary.ntlm_uid
        assert credentials["alice"][2] != ""
    finally:
        server.stop()


def test_auth_attempts_are_logged(tmp_path):
    canary, logger = make_canary(tmp_path)

    canary._log_auth_attempt(
        smbServer=None,
        connData={"ClientIP": "10.0.0.5", "ClientPort": 52901},
        domain_name="WORKGROUP",
        user_name="alice",
        host_name="CLIENT01",
    )

    assert len(logger.events) == 1
    event = logger.events[0]
    assert event["logdata"]["AUDITACTION"] == "login"
    assert event["logdata"]["STATUS"] == "fail"
    assert event["logdata"]["USER"] == "alice"
    assert event["logdata"]["DOMAIN"] == "WORKGROUP"



def test_ntlm_mode_logs_blank_authenticated_session_as_failed(tmp_path):
    canary, logger = make_canary(
        tmp_path,
        **{
            "smb.auth_mode": AUTH_MODE_NTLM,
            "smb.ntlm_username": "alice",
            "smb.ntlm_password": "secret",
        }
    )

    canary._log_auth_attempt(
        smbServer=None,
        connData={
            "Authenticated": True,
            "ClientIP": "10.0.0.5",
            "ClientPort": 52901,
        },
        domain_name="",
        user_name="",
        host_name="CLIENT01",
    )

    assert logger.events[0]["logdata"]["AUDITACTION"] == "login"
    assert logger.events[0]["logdata"]["STATUS"] == "fail"
    assert logger.events[0]["logdata"]["USER"] == "anonymous"


def test_smb_log_event_preserves_existing_alert_contract(tmp_path):
    canary, logger = make_canary(
        tmp_path,
        **{
            "device.listen_addr": "127.0.0.1",
            "smb.port": 1445,
            "smb.share_name": "docs",
            "smb.server_name": "FILE01",
        }
    )
    filename = Path(canary.share_path) / "Public" / "Readme.txt"
    filename.parent.mkdir()
    filename.write_text("hello", encoding="utf-8")

    canary._log_smb_event(
        conn_data={
            "ClientIP": "10.0.0.5",
            "ClientPort": 52901,
            "ConnectedShares": {7: {"shareName": "docs"}},
            "user_domain_name": "WORKGROUP",
            "user_name": "",
        },
        audit_action="open",
        filename=str(filename),
        smb_version="SMB2",
        tree_id=7,
    )

    assert len(logger.events) == 1
    event = logger.events[0]
    assert event["logtype"] == LoggerBase.LOG_SMB_FILE_OPEN
    assert event["src_host"] == "10.0.0.5"
    assert event["src_port"] == 52901
    assert event["dst_host"] == "127.0.0.1"
    assert event["dst_port"] == 1445
    assert event["logdata"] == {
        "USER": "anonymous",
        "REMOTENAME": "10.0.0.5",
        "SHARENAME": "docs",
        "LOCALNAME": "FILE01",
        "SMBVER": "SMB2",
        "SMBARCH": "",
        "DOMAIN": "WORKGROUP",
        "AUDITACTION": "open",
        "STATUS": "ok",
        "FILENAME": str(Path("Public") / "Readme.txt"),
    }


def test_safe_file_jail_rejects_commonprefix_sibling(tmp_path):
    share_path = tmp_path / "share"
    share_path.mkdir()
    sibling_path = tmp_path / "share_evil"
    sibling_path.mkdir()

    assert CanarySamba._safe_is_in_file_jail(
        str(share_path), "Public/Readme.txt"
    )
    assert not CanarySamba._safe_is_in_file_jail(
        str(share_path), "../share_evil/secret.txt"
    )


def test_build_server_installs_safe_file_jail(tmp_path):
    from impacket import smbserver

    share_path = tmp_path / "share"
    share_path.mkdir()
    sibling_path = tmp_path / "share_evil"
    sibling_path.mkdir()
    canary, _logger = make_canary(tmp_path, **{"smb.share_path": str(share_path)})
    server = canary._build_server()
    try:
        assert not smbserver.isInFileJail(str(share_path), "../share_evil/secret.txt")
    finally:
        server.stop()


def test_ntlm_mode_rejects_blank_successful_session_setup(tmp_path):
    canary, _logger = make_canary(
        tmp_path,
        **{
            "smb.auth_mode": AUTH_MODE_NTLM,
            "smb.ntlm_username": "alice",
            "smb.ntlm_password": "secret",
        }
    )
    server = FakeSMBServer({"Authenticated": True, "user_name": ""})

    response = canary._guard_session_setup(
        "conn1",
        server,
        ([], None, 0),
        STATUS_LOGON_FAILURE,
        STATUS_MORE_PROCESSING_REQUIRED,
    )

    assert response[2] == STATUS_LOGON_FAILURE
    assert server.conn_data["Authenticated"] is False


def test_ntlm_mode_allows_incomplete_ntlm_handshake(tmp_path):
    canary, _logger = make_canary(
        tmp_path,
        **{
            "smb.auth_mode": AUTH_MODE_NTLM,
            "smb.ntlm_username": "alice",
            "smb.ntlm_password": "secret",
        }
    )

    status = canary._session_setup_rejection_status(
        {"Authenticated": True, "user_name": ""},
        ([], None, STATUS_MORE_PROCESSING_REQUIRED),
        STATUS_LOGON_FAILURE,
        STATUS_MORE_PROCESSING_REQUIRED,
    )

    assert status is None


def test_smb2_file_id_logging_uses_requested_handle(tmp_path):
    canary, _logger = make_canary(tmp_path)
    first_id = b"1" * 16
    second_id = b"2" * 16
    first_path = str(Path(canary.share_path) / "first.txt")
    second_path = str(Path(canary.share_path) / "second.txt")
    conn_data = {
        "OpenedFiles": {
            first_id: {"FileName": first_path},
            second_id: {"FileName": second_path},
        },
        "LastRequest": {},
    }
    read_request = smb2.SMB2Read()
    read_request["FileID"] = first_id
    recv_packet = {"Data": read_request.getData(), "TreeID": 7}

    assert (
        canary._filename_from_smb2_file_id(conn_data, recv_packet, smb2.SMB2Read)
        == first_path
    )


def test_smb2_file_id_event_logs_requested_handle_not_last_opened(tmp_path):
    canary, logger = make_canary(
        tmp_path,
        **{
            "device.listen_addr": "127.0.0.1",
            "smb.share_name": "docs",
            "smb.server_name": "FILE01",
        }
    )
    first_id = b"1" * 16
    second_id = b"2" * 16
    first_path = str(Path(canary.share_path) / "first.txt")
    second_path = str(Path(canary.share_path) / "second.txt")
    conn_data = {
        "ClientIP": "10.0.0.5",
        "ClientPort": 52901,
        "ConnectedShares": {7: {"shareName": "docs", "path": canary.share_path}},
        "OpenedFiles": {
            first_id: {"FileName": first_path},
            second_id: {"FileName": second_path},
        },
        "LastRequest": {},
        "user_domain_name": "WORKGROUP",
        "user_name": "alice",
    }
    read_request = smb2.SMB2Read()
    read_request["FileID"] = first_id
    recv_packet = {"Data": read_request.getData(), "TreeID": 7}

    canary._log_smb2_file_id(
        "conn1",
        FakeSMBServer(conn_data),
        recv_packet,
        ([], None, 0),
        "read",
        smb2.SMB2Read,
    )

    assert logger.events[0]["logdata"]["AUDITACTION"] == "read"
    assert logger.events[0]["logdata"]["FILENAME"] == "first.txt"


def test_smb2_create_logs_requested_filename_even_when_open_fails(tmp_path):
    canary, _logger = make_canary(tmp_path)
    create_request = smb2.SMB2Create()
    filename = "Missing.txt".encode("utf-16le")
    create_request["NameLength"] = len(filename)
    create_request["Buffer"] = filename
    recv_packet = {"Data": create_request.getData(), "TreeID": 7}

    assert canary._filename_from_smb2_create(
        recv_packet, smb2.SMB2Create
    ) == str(Path(canary.share_path) / "Missing.txt")


def test_stop_service_does_not_block_on_hung_impacket_shutdown():
    fake_server = FakeImpacketServer()
    fake_thread = FakeAliveThread()
    service = ImpacketSMBService(fake_server)
    service.SHUTDOWN_TIMEOUT = 0.01
    service.thread = fake_thread

    service.stopService()
    try:
        assert fake_server.tcp_server.shutdown_started.is_set()
        assert fake_server.stopped is True
        assert fake_thread.join_timeout == service.SHUTDOWN_TIMEOUT
    finally:
        fake_server.tcp_server.release_shutdown.set()

