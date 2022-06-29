from opencanary.modules import CanaryService

from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.application import internet


class ProtocolError(Exception):
    pass

class GitCommandLengthMismatch(Exception):
    pass


class GitProtocol(Protocol):
    """
    Implementation of Git-daemon up to request
    """

    def _checkDataLength(self, data):
        try:
            actual_length = len(data)
            indata_length = int(data[0:4],base=16)
            if actual_length < indata_length:
                raise GitCommandLengthMismatch()
            elif actual_length > indata_length:
                raise ProtocolError()
        except ValueError:
            return False

    def _buildResponseAndSend(self, command):
        project = command[17:17 + command[17:].find('host')]
        request = command[command.find('=')+1:]
        self._logAlert(project, request)
        pre_response = 'ERR no such repository: ' + project
        response_size = '{:04x}'.format(int(len(pre_response) + 4))
        response = response_size + pre_response
        self.transport.write(response.encode() + '\n'.encode())

    def _logAlert(self, project, request):
        logdata = {"REPO": project[:-1],
                   "HOST": request[:-1]}
        self.factory.log(logdata, transport=self.transport)

    def dataReceived(self, data):
        """
        Received data is unbuffered so we buffer it for telnet.
        """
        try:
            try:
                if not hasattr(self, '_data'):
                    self._data = data
                else:
                    self._data += data

                self._checkDataLength(self._data)

                git_command = self._data[4:]
                if git_command[:15] == b'git-upload-pack':
                    self._buildResponseAndSend(git_command.decode('utf-8'))
                else:
                    raise ProtocolError()

            except GitCommandLengthMismatch:
                pass

        except ProtocolError:
            self.transport.loseConnection()
            return


class CanaryGit(Factory, CanaryService):
    NAME = 'git'
    protocol = GitProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = config.getVal("git.port", default=9418)
        self.logtype = logger.LOG_GIT_CLONE_REQUEST

    def getService(self):
        return internet.TCPServer(self.port, self)
