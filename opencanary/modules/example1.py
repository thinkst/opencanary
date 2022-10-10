from opencanary.modules import CanaryService

from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.application import internet

class Example1Protocol(Protocol):
    """
    Example Telnet Protocol

    $ telnet localhost 8025
    Trying 127.0.0.1...
    Connected to localhost.
    Escape character is '^]'.
    password:
    password:
    password:
    % Bad passwords
    Connection closed by foreign host.

    Nmap's version detection is convinced:

    $ nmap -sV 127.0.0.1 -p 8025
    Starting Nmap 6.47 ( http://nmap.org ) at 2015-07-24 11:40 SAST
    Nmap scan report for localhost (127.0.0.1)
    Host is up (0.000079s latency).
    PORT     STATE SERVICE VERSION
    8025/tcp open  telnet  D-Link ADSL router telnetd
    Service Info: Device: router
    """
    def __init__(self):
        self.prompts = 0
        self.buffer = ""

    def connectionMade(self):
        self.transport.write("\xff\xfb\x03\xff\xfb\x01password: ")
        self.prompts += 1

    def dataReceived(self, data):
        """
        Recieved data is unbuffered so we buffer it for telnet.
        """
        self.buffer += data
        print("Recieved data: ", repr(data))

        # Discard inital telnet client control chars
        i = self.buffer.find("\x01")
        if i >= 0:
            self.buffer = self.buffer[i+1:]
            return

        if self.buffer.find("\x00") >= 0:
            password = self.buffer.strip("\r\n\x00")
            logdata = {"PASSWORD" : password}
            self.factory.log(logdata, transport=self.transport)
            self.buffer = ""

            if self.prompts < 3:
                self.transport.write("\r\npassword: ")
                self.prompts += 1
            else:
                self.transport.write("\r\n% Bad passwords\r\n")
                self.transport.loseConnection()

class CanaryExample1(Factory, CanaryService):
    NAME = 'example1'
    protocol = Example1Protocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config, logger)
        self.port = config.getVal("example1.port", 8025)
        self.logtype = logger.LOG_BASE_EXAMPLE

CanaryServiceFactory = CanaryExample1
