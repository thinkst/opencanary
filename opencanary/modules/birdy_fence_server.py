import json
import os
import re
from typing import Any, Dict

from twisted.application import internet
from twisted.web.server import Site, GzipEncoderFactory
from twisted.web.resource import Resource, EncodingResourceWrapper
from twisted.web.util import Redirect
from twisted.web import static

from opencanary import config
from opencanary.modules.http import CanaryHTTP, Error, StaticNoDirListing
from opencanary.modules import CanaryService

BIRDY_FENCE_SERVER = "birdy_fence_server"


class OpenCanaryConfigService(Resource):
    isLeaf = True

    def __init__(self, factory: 'BirdyFenceServer'):
        self.factory = factory
        self.skin = self.factory.skin
        self.skindir = self.factory.skindir

        if not os.path.isdir(self.skindir):
            raise Exception(
                "Directory %s for http skin, %s, does not exist."
                % (self.skindir, self.skin)
            )

        with open(os.path.join(self.skindir, "index.html")) as f:
            text = f.read()

        p = re.compile(r"<!--STARTERR-->.*<!--ENDERR-->", re.DOTALL)
        self.login = re.sub(p, "", text)
        self.err = re.sub(r"<!--STARTERR-->|<!--ENDERR-->", "", text)
        Resource.__init__(self)

    def render(self, request):
        request.setHeader("Server", self.factory.banner)
        return Resource.render(self, request)

    def render_GET(self, request, loginFailed=False) -> bytes:
        self._log_msg("Processing GET...")
        return self._reload_config()

    def render_POST(self, request) -> bytes:
        self._log_msg("Processing POST...")
        return self._reload_config()

    def _log_msg(self, msg: str) -> None:
        """Log some text."""
        logdata = {"msg": msg}
        self.factory.logger.log(logdata)

    def _reload_config(self) -> bytes:
        """Reload the appropriate opencanary.conf into an in-memory Config object."""
        config.config = config.load_config()
        return config.config.toJSON().encode()


class RedirectCustomHeaders(Redirect):
    def __init__(self, request, factory):
        Redirect.__init__(self, request)
        self.factory = factory

    def render(self, request):
        request.setHeader(b"Server", self.factory.banner)
        return Redirect.render(self, request)


class BirdyFenceServer(CanaryService):
    NAME = BIRDY_FENCE_SERVER

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.skin = config.getVal(f"{BIRDY_FENCE_SERVER}.skin", default="basicLogin")
        self.skindir = config.getVal(f"{BIRDY_FENCE_SERVER}.skindir", default="")
        self.logger = logger

        if not os.path.isdir(self.skindir):
            self.skindir = os.path.join(CanaryHTTP.resource_dir(), "skin", self.skin)

        self.staticdir = os.path.join(self.skindir, "static")
        self.port = int(config.getVal(f"{BIRDY_FENCE_SERVER}.port", default=80))
        ubanner = config.getVal(f"{BIRDY_FENCE_SERVER}.banner", default="Apache/2.2.22 (Ubuntu)")
        self.banner = ubanner.encode("utf8")
        StaticNoDirListing.BANNER = self.banner
        self.listen_addr = config.getVal("device.listen_addr", default="")

    def getService(self):
        print(f"Getting {type(self)} service...")
        page = OpenCanaryConfigService(factory=self)
        root = StaticNoDirListing(self.staticdir)
        root.createErrorPages(self)
        root.putChild(b"", RedirectCustomHeaders(b"/index.html", factory=self))
        root.putChild(b"index.html", page)
        wrapped = EncodingResourceWrapper(root, [GzipEncoderFactory()])
        site = Site(wrapped)
        return internet.TCPServer(self.port, site, interface=self.listen_addr)
