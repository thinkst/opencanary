from opencanary.modules import CanaryService

from twisted.application import internet
from twisted.web.server import Site, GzipEncoderFactory
from twisted.web.resource import Resource, EncodingResourceWrapper, ForbiddenResource
from twisted.web.util import Redirect
from twisted.web import static

import os
import re


class Error(Resource):
    isLeaf = True

    def __init__(self, factory, error_code="404"):
        self.factory = factory
        self.skin = self.factory.skin
        self.skindir = self.factory.skindir
        self.error_code = error_code

        if not os.path.isdir(self.skindir):
            raise Exception(
                "Directory %s for http skin, %s, does not exist." %
                                          (self.skindir,self.skin))

        with open(os.path.join(self.skindir, error_code+".html")) as f:
            self.error_contents = f.read()

        Resource.__init__(self)

    def err_page(self, request):
        path = request.path\
                .replace('<', '&lt;')\
                .replace('>', '&gt;')
        return self.error_contents\
                .replace('[[URL]]', path)\
                .replace('[[BANNER]]', self.factory.banner)

    def render(self, request):
        request.setHeader('Server', self.factory.banner)
        request.setResponseCode(int(self.error_code))
        return Resource.render(self, request)

    def render_GET(self, request):
        return self.err_page(request)

    def render_POST(self, request):
        return self.err_page(request)

class BasicLogin(Resource):
    isLeaf = True

    def __init__(self, factory):
        self.factory = factory
        self.skin = self.factory.skin
        self.skindir = self.factory.skindir

        if not os.path.isdir(self.skindir):
            raise Exception(
                "Directory %s for http skin, %s, does not exist." 
                                       % (self.skindir, self.skin))

        with open(os.path.join(self.skindir, "index.html")) as f:
            text = f.read()

        p = re.compile(r"<!--STARTERR-->.*<!--ENDERR-->", re.DOTALL)
        self.login = re.sub(p, "", text)
        self.err = re.sub(r"<!--STARTERR-->|<!--ENDERR-->", "", text)
        Resource.__init__(self)

    def render(self, request):
        request.setHeader('Server', self.factory.banner)
        return Resource.render(self, request)

    def render_GET(self, request, loginFailed=False):
        if not loginFailed:
            us = request.transport.getHost()
            peer = request.transport.getPeer()
            useragent = request.getHeader('user-agent')
            if not useragent:
                useragent = '<not supplied>'

            logdata = {
                'SKIN': self.skin,
                'HOSTNAME': request.getRequestHostname(),
                'PATH': request.path,
                'USERAGENT': useragent
            }

            logtype = self.factory.logger.LOG_HTTP_GET
            self.factory.log(logdata, transport=request.transport, logtype=logtype)

        return self.login

    def render_POST(self, request):
        try:
            username = request.args['username'][0]
        except KeyError, IndexError:
            username = '<not supplied>'
        try:
            password = request.args['password'][0]
        except KeyError, IndexError:
            password = '<not supplied>'
        useragent = request.getHeader('user-agent')
        if not useragent:
            useragent = '<not supplied>'

        logdata = {
            'USERNAME': username,
            'PASSWORD': password,
            'SKIN': self.skin,
            'HOSTNAME': request.getRequestHostname(),
            'PATH': request.path,
            'USERAGENT': useragent
        }
        logtype = self.factory.logger.LOG_HTTP_POST_LOGIN_ATTEMPT
        self.factory.log(logdata, transport=request.transport, logtype=logtype)

        return self.err


class RedirectCustomHeaders(Redirect):

    def __init__(self, request, factory):
        Redirect.__init__(self, request)
        self.factory = factory

    def render(self, request):
        request.setHeader('Server', self.factory.banner)
        return Redirect.render(self, request)


class StaticNoDirListing(static.File):
    """Web resource that serves static directory tree.

    Directory listing is not allowed, and custom headers are set.

    """

    # Banner is declared statically because Twisted creates several
    # instances of this object, where we don't control the arguments
    # for the initialisation.
    BANNER = None
    FORBIDDEN = None

    def createErrorPages(self, factory):
        self.childNotFound = Error(factory, error_code="404")
        StaticNoDirListing.FORBIDDEN = Error(factory, error_code="403")

    def directoryListing(self):
        return StaticNoDirListing.FORBIDDEN

    def getChild(self, name, request):
        request.setHeader('Server', StaticNoDirListing.BANNER)
        return static.File.getChild(self, name, request)


class CanaryHTTP(CanaryService):
    NAME = 'http'

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.skin = config.getVal('http.skin', default='basicLogin')
        self.skindir = os.path.join(
            CanaryHTTP.resource_dir(), "skin", self.skin)
        self.staticdir = os.path.join(self.skindir, "static")
        self.port = int(config.getVal('http.port', default=80))
        ubanner = config.getVal('http.banner', default="Apache/2.2.22 (Ubuntu)")
        self.banner = ubanner.encode('utf8')
        StaticNoDirListing.BANNER = self.banner
        self.listen_addr = config.getVal('device.listen_addr', default='')

    def getService(self):
        page = BasicLogin(factory=self)
        root = StaticNoDirListing(self.staticdir)
        root.createErrorPages(self)
        root.putChild("", RedirectCustomHeaders("/index.html", factory=self))
        root.putChild("index.html", page)
        wrapped = EncodingResourceWrapper(root, [GzipEncoderFactory()])
        site = Site(wrapped)
        return internet.TCPServer(self.port, site, interface=self.listen_addr)
