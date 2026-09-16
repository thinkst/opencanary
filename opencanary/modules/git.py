from opencanary.modules import CanaryService

from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.application import internet
from twisted.protocols.policies import LimitTotalConnectionsFactory, TimeoutMixin

DEFAULT_MAX_CONNECTIONS = 32
DEFAULT_TIMEOUT = 10
MAX_PACKET_SIZE = 65520


class ProtocolError(Exception):
    pass


class GitCommandLengthMismatch(Exception):
    pass


class GitProtocol(TimeoutMixin, Protocol):
    """
    Implementation of Git-daemon up to request
    """

    def connectionMade(self):
        self._data = b""
        self._received_bytes = 0
        self.setTimeout(self.factory.timeout)

    def connectionLost(self, reason):
        self.setTimeout(None)

    def callLater(self, period, func):
        return getattr(self.factory, "reactor", reactor).callLater(period, func)

    def timeoutConnection(self):
        self._disconnect()

    def _disconnect(self):
        self.setTimeout(None)
        self._data = b""
        self.transport.loseConnection()

    def _checkDataLength(self, data):
        if len(data) < 4:
            raise GitCommandLengthMismatch()

        try:
            actual_length = len(data)
            indata_length = int(data[0:4], base=16)
            if indata_length > MAX_PACKET_SIZE:
                raise ProtocolError()
            if actual_length < indata_length:
                raise GitCommandLengthMismatch()
            elif actual_length > indata_length:
                raise ProtocolError()
        except ValueError:
            raise ProtocolError()

    def _buildResponseAndSend(self, command):
        project = command[17 : 17 + command[17:].find("host")]
        request = command[command.find("=") + 1 :]
        self._logAlert(project, request)
        pre_response = "ERR no such repository: " + project
        response_size = "{:04x}".format(int(len(pre_response) + 4))
        response = response_size + pre_response
        self.transport.write(response.encode() + "\n".encode())

    def _logAlert(self, project, request):
        logdata = {"REPO": project[:-1], "HOST": request[:-1]}
        self.factory.log(logdata, transport=self.transport)

    def dataReceived(self, data):
        """
        Received data is unbuffered so we buffer it for telnet.
        """
        self.resetTimeout()

        self._received_bytes += len(data)
        if self._received_bytes > MAX_PACKET_SIZE:
            self._disconnect()
            return

        try:
            try:
                self._data += data

                self._checkDataLength(self._data)

                git_command = self._data[4:]
                if git_command[:15] == b"git-upload-pack":
                    self._buildResponseAndSend(git_command.decode("utf-8"))
                    self._data = b""
                else:
                    raise ProtocolError()

            except GitCommandLengthMismatch:
                pass

        except ProtocolError:
            self._disconnect()
            return


class CanaryGit(LimitTotalConnectionsFactory, CanaryService):
    NAME = "git"
    protocol = GitProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = config.getVal("git.port", default=9418)
        self.connectionLimit = int(
            config.getVal("git.max_connections", default=DEFAULT_MAX_CONNECTIONS)
        )
        self.timeout = float(config.getVal("git.timeout", default=DEFAULT_TIMEOUT))
        self.connectionCount = 0
        self.reactor = reactor
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_GIT_CLONE_REQUEST

    def getService(self):
        return internet.TCPServer(self.port, self, interface=self.listen_addr)
