from opencanary.modules import CanaryService

from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.application import internet

class Example0Protocol(Protocol):
    """
     Example (Fictional) Protocol
    
    $ nc localhost 8007
    Welcome!
    password: wrong0
    password: wrong1
    password: wrong2
    Bad passwords
    $
    """

    def __init__(self):
        self.prompts = 0

    def connectionMade(self):
        self.transport.write("Welcome!\r\npassword: ")
        self.prompts += 1

    def dataReceived(self, data):
        """
        Careful, data recieved here is unbuffered. See example1
        for how this can be better handled.
        """
        password = data.strip("\r\n")
        logdata = {"PASSWORD" : password}
        self.factory.log(logdata, transport=self.transport)
        
        if self.prompts < 3:
            self.transport.write("\r\npassword: ")
            self.prompts += 1
        else:
            self.transport.write("\r\nBad passwords\r\n")
            self.transport.loseConnection()
                
class CanaryExample0(Factory, CanaryService):
    NAME = 'example0'
    protocol = Example0Protocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config, logger)
        self.port = 8007
        self.logtype = logger.LOG_BASE_EXAMPLE

CanaryServiceFactory = CanaryExample0
