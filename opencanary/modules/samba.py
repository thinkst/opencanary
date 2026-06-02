import os
import threading
from binascii import hexlify

from twisted.application import service

from opencanary.config import ConfigException
from opencanary.modules import CanaryService


AUTH_MODE_GUEST = "guest"
AUTH_MODE_NTLM = "ntlm"
AUTH_MODES = (AUTH_MODE_GUEST, AUTH_MODE_NTLM)
DEFAULT_NTLM_UID = 1000
DEFAULT_SMB_PORT = 445
DEFAULT_SHARE_NAME = "myshare"
DEFAULT_SERVER_NAME = "SRV01"
DEFAULT_SERVER_OS = "Windows Server 2019"
DEFAULT_SERVER_DOMAIN = "WORKGROUP"


class ImpacketSMBService(service.Service):
    SHUTDOWN_TIMEOUT = 5

    def __init__(self, smb_server):
        self.smb_server = smb_server
        self.thread = None

    def startService(self):
        service.Service.startService(self)
        self.thread = threading.Thread(
            target=self.smb_server.start, name="opencanary-smb"
        )
        self.thread.daemon = True
        self.thread.start()

    def stopService(self):
        server = self.smb_server.getServer()
        if self.thread is not None and self.thread.is_alive():
            shutdown_thread = threading.Thread(
                target=server.shutdown, name="opencanary-smb-shutdown"
            )
            shutdown_thread.daemon = True
            shutdown_thread.start()
            shutdown_thread.join(timeout=self.SHUTDOWN_TIMEOUT)
        self.smb_server.stop()
        if self.thread is not None:
            self.thread.join(timeout=self.SHUTDOWN_TIMEOUT)
        service.Service.stopService(self)


class CanarySamba(CanaryService):
    NAME = "smb"

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("smb.port", default=DEFAULT_SMB_PORT))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.share_name = config.getVal("smb.share_name", default=DEFAULT_SHARE_NAME)
        self.server_name = config.getVal("smb.server_name", default=DEFAULT_SERVER_NAME)
        self.server_os = config.getVal("smb.server_os", default=DEFAULT_SERVER_OS)
        self.server_domain = config.getVal(
            "smb.server_domain", default=DEFAULT_SERVER_DOMAIN
        )
        self.auth_mode = config.getVal(
            "smb.auth_mode", default=AUTH_MODE_GUEST
        ).lower()
        self.ntlm_username = config.getVal("smb.ntlm_username", default="")
        self.ntlm_password = config.getVal("smb.ntlm_password", default="")
        self.ntlm_hashes = config.getVal("smb.ntlm_hashes", default="")
        self.ntlm_lmhash = config.getVal("smb.ntlm_lmhash", default="")
        self.ntlm_nthash = config.getVal("smb.ntlm_nthash", default="")
        self.ntlm_uid = int(config.getVal("smb.ntlm_uid", default=DEFAULT_NTLM_UID))
        self.share_path = os.path.realpath(
            config.getVal("smb.share_path", default=self.resource_filename("share"))
        )
        self._validate_auth_config()

    def getService(self):
        if not os.path.isdir(self.share_path):
            raise ConfigException(
                "smb.share_path", "%s is not a directory" % self.share_path
            )
        return ImpacketSMBService(self._build_server())

    def _build_server(self):
        try:
            from impacket import ntlm, smb
            from impacket import smb3structs as smb2
            from impacket import smbserver
            from impacket.nt_errors import (
                STATUS_ACCESS_DENIED,
                STATUS_LOGON_FAILURE,
                STATUS_MORE_PROCESSING_REQUIRED,
            )
        except ImportError as exc:
            raise ConfigException(
                "smb.enabled",
                "The SMB module requires the impacket Python package",
            ) from exc

        self._install_safe_path_jail(smbserver)
        server = smbserver.SimpleSMBServer(
            listenAddress=self.listen_addr,
            listenPort=self.port,
        )
        server.addShare(
            self.share_name,
            self.share_path,
            "OpenCanary Windows file share",
            readOnly="yes",
        )
        server.setSMB2Support(True)
        self._set_server_identity(server)
        self._configure_authentication(server, ntlm)
        self._install_smb_hooks(
            server.getServer(),
            smb,
            smb2,
            STATUS_ACCESS_DENIED,
            STATUS_LOGON_FAILURE,
            STATUS_MORE_PROCESSING_REQUIRED,
        )
        return server

    def _install_safe_path_jail(self, smbserver):
        smbserver.isInFileJail = self._safe_is_in_file_jail

    @staticmethod
    def _safe_is_in_file_jail(path, file_name):
        share_path = os.path.realpath(path)
        requested_path = os.path.realpath(os.path.join(share_path, file_name))
        try:
            return os.path.commonpath([share_path, requested_path]) == share_path
        except ValueError:
            return False

    def _validate_auth_config(self):
        if self.auth_mode not in AUTH_MODES:
            raise ConfigException(
                "smb.auth_mode",
                "Unsupported authentication mode %s. Use guest or ntlm."
                % self.auth_mode,
            )
        if self.auth_mode != AUTH_MODE_NTLM:
            return
        if not self.ntlm_username:
            raise ConfigException(
                "smb.ntlm_username", "NTLM authentication requires a username"
            )
        if not (self.ntlm_password or self.ntlm_hashes or self.ntlm_nthash):
            raise ConfigException(
                "smb.ntlm_password",
                "NTLM authentication requires a password, ntlm_hashes, or ntlm_nthash",
            )

    def _set_server_identity(self, server):
        config = server.getServer().getServerConfig()
        config.set("global", "server_name", self.server_name)
        config.set("global", "server_os", self.server_os)
        config.set("global", "server_domain", self.server_domain)
        server.getServer().setServerConfig(config)
        server.getServer().processConfigFile()

    def _configure_authentication(self, server, ntlm):
        server.setNTLMSupport(True)
        server.setKerberosSupport(False)
        config = server.getServer().getServerConfig()
        config.set(
            "global",
            "anonymous_logon",
            "False" if self.auth_mode == AUTH_MODE_NTLM else "True",
        )
        server.getServer().setServerConfig(config)
        server.getServer().processConfigFile()
        server.setAuthCallback(self._log_auth_attempt)

        if self.auth_mode == AUTH_MODE_NTLM:
            lmhash, nthash = self._ntlm_credential_hashes(ntlm)
            server.addCredential(self.ntlm_username, self.ntlm_uid, lmhash, nthash)

    def _ntlm_credential_hashes(self, ntlm):
        if self.ntlm_password:
            return (
                hexlify(ntlm.compute_lmhash(self.ntlm_password)).decode("ascii"),
                hexlify(ntlm.compute_nthash(self.ntlm_password)).decode("ascii"),
            )
        if self.ntlm_hashes:
            try:
                lmhash, nthash = self.ntlm_hashes.split(":", 1)
            except ValueError as exc:
                raise ConfigException(
                    "smb.ntlm_hashes", "Expected LMHASH:NTHASH format"
                ) from exc
            return lmhash, nthash
        return (
            self.ntlm_lmhash or hexlify(ntlm.DEFAULT_LM_HASH).decode("ascii"),
            self.ntlm_nthash,
        )

    def _install_smb_hooks(
        self,
        smb_server,
        smb,
        smb2,
        status_access_denied,
        status_logon_failure,
        status_more_processing_required,
    ):
        self._hook_smb1_session_setup(
            smb_server,
            smb.SMB.SMB_COM_SESSION_SETUP_ANDX,
            status_logon_failure,
            status_more_processing_required,
        )
        self._hook_smb2_session_setup(
            smb_server,
            smb2.SMB2_SESSION_SETUP,
            status_logon_failure,
            status_more_processing_required,
        )
        self._hook_smb1_tree_connect(
            smb_server,
            smb.SMB.SMB_COM_TREE_CONNECT_ANDX,
            self._log_smb1_tree_connect,
            "connect",
            smb,
            status_access_denied,
        )
        self._hook_smb1_command(
            smb_server,
            smb.SMB.SMB_COM_NT_CREATE_ANDX,
            self._log_smb1_filename,
            "open",
            smb.SMBNtCreateAndX_Data,
        )
        self._hook_smb1_command(
            smb_server,
            smb.SMB.SMB_COM_OPEN_ANDX,
            self._log_smb1_filename,
            "open",
            smb.SMBOpenAndX_Data,
        )
        self._hook_smb2_tree_connect(
            smb_server,
            smb2.SMB2_TREE_CONNECT,
            self._log_smb2_tree_connect,
            "connect",
            smb2,
            status_access_denied,
        )
        self._hook_smb2_command(
            smb_server,
            smb2.SMB2_CREATE,
            self._log_smb2_create,
            "open",
            smb2.SMB2Create,
        )
        self._hook_smb2_command(
            smb_server,
            smb2.SMB2_QUERY_DIRECTORY,
            self._log_smb2_file_id,
            "list",
            smb2.SMB2QueryDirectory,
        )
        self._hook_smb2_command(
            smb_server,
            smb2.SMB2_READ,
            self._log_smb2_file_id,
            "read",
            smb2.SMB2Read,
        )
        self._hook_smb2_command(
            smb_server,
            smb2.SMB2_WRITE,
            self._log_smb2_file_id,
            "write",
            smb2.SMB2Write,
        )
        self._hook_smb2_command(
            smb_server,
            smb2.SMB2_SET_INFO,
            self._log_smb2_file_id,
            "set_info",
            smb2.SMB2SetInfo,
        )

    def _hook_smb1_command(
        self, smb_server, command, log_callback, audit_action, *log_args
    ):
        original = smb_server.hookSmbCommand(command, None)
        smb_server.hookSmbCommand(
            command,
            self._make_smb1_hook(original, log_callback, audit_action, *log_args),
        )

    def _make_smb1_hook(self, original, log_callback, audit_action, *log_args):
        def hook(conn_id, smb_server, smb_command, recv_packet):
            response = original(conn_id, smb_server, smb_command, recv_packet)
            log_callback(
                conn_id,
                smb_server,
                smb_command,
                recv_packet,
                response,
                audit_action,
                *log_args
            )
            return response

        return hook

    def _hook_smb1_session_setup(
        self,
        smb_server,
        command,
        status_logon_failure,
        status_more_processing_required,
    ):
        original = smb_server.hookSmbCommand(command, None)
        smb_server.hookSmbCommand(
            command,
            self._make_smb1_session_setup_hook(
                original, status_logon_failure, status_more_processing_required
            ),
        )

    def _make_smb1_session_setup_hook(
        self, original, status_logon_failure, status_more_processing_required
    ):
        def hook(conn_id, smb_server, smb_command, recv_packet):
            response = original(conn_id, smb_server, smb_command, recv_packet)
            return self._guard_session_setup(
                conn_id,
                smb_server,
                response,
                status_logon_failure,
                status_more_processing_required,
            )

        return hook

    def _hook_smb1_tree_connect(
        self,
        smb_server,
        command,
        log_callback,
        audit_action,
        smb,
        status_access_denied,
    ):
        original = smb_server.hookSmbCommand(command, None)
        smb_server.hookSmbCommand(
            command,
            self._make_smb1_tree_connect_hook(
                original, log_callback, audit_action, smb, status_access_denied
            ),
        )

    def _make_smb1_tree_connect_hook(
        self, original, log_callback, audit_action, smb, status_access_denied
    ):
        def hook(conn_id, smb_server, smb_command, recv_packet):
            conn_data = smb_server.getConnectionData(conn_id)
            if self._deny_unauthenticated_tree_connect(conn_data):
                response = (
                    [smb.SMBCommand(recv_packet["Command"])],
                    None,
                    status_access_denied,
                )
                log_callback(
                    conn_id,
                    smb_server,
                    smb_command,
                    recv_packet,
                    response,
                    audit_action,
                )
                return response
            response = original(conn_id, smb_server, smb_command, recv_packet)
            log_callback(
                conn_id, smb_server, smb_command, recv_packet, response, audit_action
            )
            return response

        return hook

    def _hook_smb2_command(
        self, smb_server, command, log_callback, audit_action, *log_args
    ):
        original = smb_server.hookSmb2Command(command, None)
        smb_server.hookSmb2Command(
            command,
            self._make_smb2_hook(original, log_callback, audit_action, *log_args),
        )

    def _make_smb2_hook(self, original, log_callback, audit_action, *log_args):
        def hook(conn_id, smb_server, recv_packet):
            response = original(conn_id, smb_server, recv_packet)
            log_callback(
                conn_id, smb_server, recv_packet, response, audit_action, *log_args
            )
            return response

        return hook

    def _hook_smb2_session_setup(
        self,
        smb_server,
        command,
        status_logon_failure,
        status_more_processing_required,
    ):
        original = smb_server.hookSmb2Command(command, None)
        smb_server.hookSmb2Command(
            command,
            self._make_smb2_session_setup_hook(
                original, status_logon_failure, status_more_processing_required
            ),
        )

    def _make_smb2_session_setup_hook(
        self, original, status_logon_failure, status_more_processing_required
    ):
        def hook(conn_id, smb_server, recv_packet):
            response = original(conn_id, smb_server, recv_packet)
            return self._guard_session_setup(
                conn_id,
                smb_server,
                response,
                status_logon_failure,
                status_more_processing_required,
            )

        return hook

    def _hook_smb2_tree_connect(
        self,
        smb_server,
        command,
        log_callback,
        audit_action,
        smb2,
        status_access_denied,
    ):
        original = smb_server.hookSmb2Command(command, None)
        smb_server.hookSmb2Command(
            command,
            self._make_smb2_tree_connect_hook(
                original, log_callback, audit_action, smb2, status_access_denied
            ),
        )

    def _make_smb2_tree_connect_hook(
        self, original, log_callback, audit_action, smb2, status_access_denied
    ):
        def hook(conn_id, smb_server, recv_packet):
            conn_data = smb_server.getConnectionData(conn_id)
            if self._deny_unauthenticated_tree_connect(conn_data):
                response = (
                    [smb2.SMB2TreeConnect_Response()],
                    None,
                    status_access_denied,
                )
                log_callback(conn_id, smb_server, recv_packet, response, audit_action)
                return response
            response = original(conn_id, smb_server, recv_packet)
            log_callback(conn_id, smb_server, recv_packet, response, audit_action)
            return response

        return hook

    def _deny_unauthenticated_tree_connect(self, conn_data):
        return (
            self.auth_mode == AUTH_MODE_NTLM
            and self._username(conn_data) == "anonymous"
        )

    def _guard_session_setup(
        self,
        conn_id,
        smb_server,
        response,
        status_logon_failure,
        status_more_processing_required,
    ):
        conn_data = smb_server.getConnectionData(conn_id, checkStatus=False)
        rejection_status = self._session_setup_rejection_status(
            conn_data,
            response,
            status_logon_failure,
            status_more_processing_required,
        )
        if rejection_status is None:
            return response
        conn_data["Authenticated"] = False
        smb_server.setConnectionData(conn_id, conn_data)
        return response[0], response[1], rejection_status

    def _session_setup_rejection_status(
        self,
        conn_data,
        response,
        status_logon_failure,
        status_more_processing_required,
    ):
        status = self._response_status(response)
        if status == status_more_processing_required:
            return None
        if status != 0:
            return status
        if (
            self.auth_mode == AUTH_MODE_NTLM
            and self._username(conn_data) == "anonymous"
        ):
            return status_logon_failure
        return None

    def _log_auth_attempt(
        self, smbServer, connData, domain_name, user_name, host_name
    ):
        conn_data = dict(connData)
        conn_data["user_domain_name"] = domain_name or host_name
        conn_data["user_name"] = user_name
        authenticated = connData.get("Authenticated") and not (
            self.auth_mode == AUTH_MODE_NTLM and not user_name
        )
        self._log_smb_event(
            conn_data=conn_data,
            audit_action="login",
            filename="",
            smb_version="SMB",
            status=0 if authenticated else 1,
        )

    def _log_smb1_tree_connect(
        self, conn_id, smb_server, smb_command, recv_packet, response, audit_action
    ):
        self._log_smb_event(
            conn_data=smb_server.getConnectionData(conn_id),
            audit_action=audit_action,
            filename="",
            smb_version="SMB1",
            status=self._response_status(response),
            tree_id=recv_packet["Tid"],
        )

    def _log_smb1_filename(
        self,
        conn_id,
        smb_server,
        smb_command,
        recv_packet,
        response,
        audit_action,
        request_data_cls,
    ):
        conn_data = smb_server.getConnectionData(conn_id)
        self._log_smb_event(
            conn_data=conn_data,
            audit_action=audit_action,
            filename=self._filename_from_smb1_request(
                conn_data, smb_command, recv_packet, request_data_cls
            ),
            smb_version="SMB1",
            status=self._response_status(response),
            tree_id=recv_packet["Tid"],
        )

    def _log_smb2_tree_connect(
        self, conn_id, smb_server, recv_packet, response, audit_action
    ):
        self._log_smb_event(
            conn_data=smb_server.getConnectionData(conn_id),
            audit_action=audit_action,
            filename="",
            smb_version="SMB2",
            status=self._response_status(response),
            tree_id=recv_packet["TreeID"],
        )

    def _log_smb2_create(
        self, conn_id, smb_server, recv_packet, response, audit_action, request_cls
    ):
        self._log_smb_event(
            conn_data=smb_server.getConnectionData(conn_id),
            audit_action=audit_action,
            filename=self._filename_from_smb2_create(recv_packet, request_cls),
            smb_version="SMB2",
            status=self._response_status(response),
            tree_id=recv_packet["TreeID"],
        )

    def _log_smb2_file_id(
        self, conn_id, smb_server, recv_packet, response, audit_action, request_cls
    ):
        conn_data = smb_server.getConnectionData(conn_id)
        self._log_smb_event(
            conn_data=conn_data,
            audit_action=audit_action,
            filename=self._filename_from_smb2_file_id(
                conn_data, recv_packet, request_cls
            ),
            smb_version="SMB2",
            status=self._response_status(response),
            tree_id=recv_packet["TreeID"],
        )

    def _log_smb_event(
        self,
        conn_data,
        audit_action,
        filename,
        smb_version,
        status=0,
        tree_id=None,
    ):
        share_name = self._share_name(conn_data, tree_id)
        self.logger.log(
            {
                "src_host": conn_data.get("ClientIP", ""),
                "src_port": conn_data.get("ClientPort", -1),
                "dst_host": self.listen_addr,
                "dst_port": self.port,
                "logtype": self.logger.LOG_SMB_FILE_OPEN,
                "logdata": {
                    "USER": self._username(conn_data),
                    "REMOTENAME": conn_data.get("ClientIP", ""),
                    "SHARENAME": share_name,
                    "LOCALNAME": self.server_name,
                    "SMBVER": smb_version,
                    "SMBARCH": "",
                    "DOMAIN": conn_data.get("user_domain_name", ""),
                    "AUDITACTION": audit_action,
                    "STATUS": self._status_text(status),
                    "FILENAME": self._relative_filename(filename),
                },
            }
        )

    def _share_name(self, conn_data, tree_id):
        if tree_id is not None:
            share = conn_data.get("ConnectedShares", {}).get(tree_id)
            if share:
                return share.get("shareName", self.share_name)
        return self.share_name

    def _username(self, conn_data):
        username = conn_data.get("user_name", "")
        if username in ("", None):
            return "anonymous"
        return username

    def _relative_filename(self, filename):
        if not filename:
            return ""
        filename = os.path.realpath(filename)
        if os.path.commonpath([self.share_path, filename]) == self.share_path:
            return os.path.relpath(filename, self.share_path)
        return filename

    def _filename_from_smb1_request(
        self, conn_data, smb_command, recv_packet, request_data_cls
    ):
        request_data = request_data_cls(
            flags=recv_packet["Flags2"], data=smb_command["Data"]
        )
        try:
            filename = request_data["FileName"]
            if isinstance(filename, bytes):
                if recv_packet["Flags2"] & 0x8000:
                    filename = filename.decode("utf-16le")
                else:
                    filename = filename.decode("ascii")
            return self._share_path_for_smb_filename(
                conn_data, recv_packet["Tid"], filename
            )
        except Exception:
            return self._best_opened_filename(conn_data)

    def _filename_from_smb2_create(self, recv_packet, request_cls):
        request = request_cls(recv_packet["Data"])
        filename = request["Buffer"][: request["NameLength"]].decode("utf-16le")
        return self._share_path_for_smb_filename(
            None, recv_packet["TreeID"], filename
        )

    def _filename_from_smb2_file_id(self, conn_data, recv_packet, request_cls):
        request = request_cls(recv_packet["Data"])
        file_id = self._smb2_request_file_id(conn_data, request)
        return self._opened_filename(conn_data, file_id)

    def _smb2_request_file_id(self, conn_data, request):
        file_id = request["FileID"].getData()
        if file_id == b"\xff" * 16 and "SMB2_CREATE" in conn_data.get(
            "LastRequest", {}
        ):
            file_id = conn_data["LastRequest"]["SMB2_CREATE"]["FileID"]
        if hasattr(file_id, "getData"):
            return file_id.getData()
        return file_id

    def _share_path_for_smb_filename(self, conn_data, tree_id, filename):
        filename = self._normalize_smb_filename(filename)
        base_path = self.share_path
        if conn_data is not None:
            share = conn_data.get("ConnectedShares", {}).get(tree_id, {})
            base_path = share.get("path", base_path)
        return os.path.join(base_path, filename)

    def _normalize_smb_filename(self, filename):
        filename = str(filename).replace("\\", "/")
        filename = os.path.normpath(filename)
        while filename.startswith("/") or filename.startswith("\\"):
            filename = filename[1:]
        return filename

    def _opened_filename(self, conn_data, file_id):
        opened_file = conn_data.get("OpenedFiles", {}).get(file_id, {})
        return opened_file.get("FileName") or opened_file.get("fileName") or ""

    def _best_opened_filename(self, conn_data):
        opened_files = conn_data.get("OpenedFiles", {})
        for opened_file in reversed(list(opened_files.values())):
            filename = opened_file.get("FileName") or opened_file.get("fileName")
            if filename:
                return filename
        return ""

    def _response_status(self, response):
        try:
            return response[2]
        except (IndexError, TypeError):
            return 0

    def _status_text(self, status):
        if status == 0:
            return "ok"
        return "fail"


CanaryServiceFactory = CanarySamba
