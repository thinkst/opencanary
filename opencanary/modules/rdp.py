from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.application import internet
from rdpy.protocol.rdp.rdp import RDPServerObserver
from rdpy.protocol.rdp.rdp import ServerFactory
from rdpy.core import rss
from rdpy.core.scancode import scancodeToChar
from opencanary.modules import CanaryService

class RDPObserver(RDPServerObserver):
    def __init__(self, factory, controller, rssFile):
        RDPServerObserver.__init__(self, controller)
        self.factory = factory
        self.buffer = ""

    def onReady(self):
        domain, username, password = self._controller.getCredentials()
        hostname = self._controller.getHostname()
        logdata = {
            "DOMAIN": domain,
            "USERNAME": username,
            "PASSWORD": password,
            "HOSTNAME": hostname
        }
        transport = self._controller.getProtocol().transport
        us = transport.getHost()
        peer = transport.getPeer()
        self.transportlog = {
            'src_host' : peer.host,
            'src_port' : peer.port,
            'dst_host' : us.host,
            'dst_port' : us.port
        }
        self.factory.log(logdata, **self.transportlog)
        self.doEvent(0)

    def onClose(self):
        if getattr(self, "transportlog", None):
            logdata = {"INPUT" : self.buffer}
            self.factory.log(logdata, **self.transportlog)

    def onKeyEventScancode(self, code, isPressed, isExtended):
        self.buffer += scancodeToChar(code)

    def onKeyEventUnicode(self, code, isPressed):
        pass

    def onPointerEvent(self, x, y, button, isPressed):
        pass

    def doEvent(self, i):
        if i >= len(self.factory.rss) - 1:
            return

        e = self.factory.rss[i]

        # TODO: handle other events (eg. the screen resize)
        if e.type.value == rss.EventType.UPDATE:
            self._controller.sendUpdate(
                e.event.destLeft.value,
                e.event.destTop.value,
                e.event.destRight.value,
                e.event.destBottom.value,
                e.event.width.value, e.event.height.value,
                e.event.bpp.value,
                e.event.format.value == rss.UpdateFormat.BMP,
                e.event.data.value)

        t = self.factory.rss[i+1].timestamp.value
        reactor.callLater(float(t) / 1000.0, self.doEvent, i + 1)

class CanaryRDP(ServerFactory, CanaryService):
    NAME = 'rdp'

    def __init__(self, config=None, logger=None):
        ServerFactory.__init__(self, 16, None, None)
        CanaryService.__init__(self, config, logger)

        self.rssFile = self.resource_filename("login.rss")
        reader = rss.createReader(self.rssFile)
        self.rss = []
        while True:
            e = reader.nextEvent()
            if e:
                self.rss.append(e)
            else:
                break

        self.port = config.getVal("rdp.port", 3389)
        self.logtype = logger.LOG_RDP

    def buildObserver(self, controller, addr):
        return RDPObserver(self, controller, self.rssFile)

CanaryServiceFactory = CanaryRDP
