from opencanary.modules import CanaryService

from twisted.application import internet
from twisted.web.server import Site, GzipEncoderFactory, Request
from twisted.web.resource import Resource, EncodingResourceWrapper
from twisted.web.http import HTTPChannel, HTTPFactory
from twisted.web.util import Redirect
from twisted.web import static

import os
import re


class CanaryRequest(Request):
    allowedMethods = [
        "GET",
        "POST",
        "DELETE",
        "PATCH",
        "PUT",
        "CONNECT",
        "TRACE",
        "HEAD",
    ]

    def process(self):
        if self.method.decode("utf-8") not in self.allowedMethods:
            self.transport.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            self.length = None
            self.transport.loseConnection()
            return
        Request.process(self)


class CanaryHttpServiceSite(Site):
    requestFactory = CanaryRequest


class CanaryHTTPChannel(HTTPChannel):
    requestFactory = CanaryRequest

    def headerReceived(self, line: bytes) -> bool:
        try:
            return HTTPChannel.headerReceived(self, line)
        except ValueError:
            self.transport.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            self.length = None
            self.transport.loseConnection()
            return


HTTPFactory.protocol = CanaryHTTPChannel


class Error(Resource):
    isLeaf = True

    def __init__(self, factory, error_code="404"):
        self.factory = factory
        self.skin = self.factory.skin
        self.skindir = self.factory.skindir
        self.error_code = error_code

        if not os.path.isdir(self.skindir):
            raise Exception(
                "Directory %s for http skin, %s, does not exist."
                % (self.skindir, self.skin)
            )

        with open(os.path.join(self.skindir, error_code + ".html")) as f:
            self.error_contents = f.read()

        Resource.__init__(self)

    def err_page(self, request):
        path = request.path.replace(b"<", b"&lt;").replace(b">", b"&gt;")
        return self.error_contents.replace("[[URL]]", path.decode("utf-8")).replace(
            "[[BANNER]]", self.factory.banner.decode("utf-8")
        )

    def render(self, request):
        request.setHeader(b"Server", self.factory.banner)
        request.setResponseCode(int(self.error_code))
        return Resource.render(self, request)

    def render_GET(self, request):
        return self.err_page(request).encode()

    def render_POST(self, request):
        return self.err_page(request).encode()

    def render_DELETE(self, request):
        return self.err_page(request).encode()

    def render_PATCH(self, request):
        return self.err_page(request).encode()

    def render_PUT(self, request):
        return self.err_page(request).encode()

    def render_HEAD(self, request):
        return self.err_page(request).encode()

    def render_CONNECT(self, request):
        return self.err_page(request).encode()

    def render_TRACE(self, request):
        return self.err_page(request).encode()


class BasicLogin(Resource):
    isLeaf = True
    EMPTY_STRING = ""

    def __init__(self, factory):
        self.factory = factory
        self.skin = self.factory.skin
        self.skindir = self.factory.skindir
        self.log_unimplemented_methods = self.factory.config.getVal(
            "http.log_unimplemented_method_requests", default=False
        )

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

    def render_GET(self, request, loginFailed=False):
        if not loginFailed:
            useragent = request.getHeader("user-agent")
            if not useragent:
                useragent = "<not supplied>"

            logdata = {
                "SKIN": self.skin,
                "HOSTNAME": request.getRequestHostname(),
                "PATH": request.path,
                "USERAGENT": useragent,
            }

            logtype = self.factory.logger.LOG_HTTP_GET
            self.factory.log(logdata, transport=request.transport, logtype=logtype)

        return self.login.encode()

    def render_POST(self, request):
        try:
            username = request.args[b"username"][0]
        except (KeyError, IndexError):
            username = "<not supplied>"
        try:
            password = request.args[b"password"][0]
        except (KeyError, IndexError):
            password = "<not supplied>"
        useragent = request.getHeader(b"user-agent")
        if not useragent:
            useragent = "<not supplied>"

        logdata = {
            "USERNAME": username,
            "PASSWORD": password,
            "SKIN": self.skin,
            "HOSTNAME": request.getRequestHostname(),
            "PATH": request.path,
            "USERAGENT": useragent,
        }
        logtype = self.factory.logger.LOG_HTTP_POST_LOGIN_ATTEMPT
        self.factory.log(logdata, transport=request.transport, logtype=logtype)

        return self.err.encode()

    def render_DELETE(self, request):
        self._log_unimplemented_method(request)
        request.setResponseCode(405)
        return self.EMPTY_STRING.encode()

    def render_PATCH(self, request: Request):
        self._log_unimplemented_method(request)
        request.setResponseCode(405)
        return self.EMPTY_STRING.encode()

    def render_PUT(self, request):
        self._log_unimplemented_method(request)
        request.setResponseCode(405)
        return self.EMPTY_STRING.encode()

    def render_HEAD(self, request):
        self._log_unimplemented_method(request)
        request.setResponseCode(405)
        return self.EMPTY_STRING.encode()

    def render_CONNECT(self, request):
        self._log_unimplemented_method(request)
        request.setResponseCode(405)
        return self.EMPTY_STRING.encode()

    def render_TRACE(self, request):
        self._log_unimplemented_method(request)
        request.setResponseCode(405)
        return self.EMPTY_STRING.encode()

    def _log_unimplemented_method(self, request):
        if self.log_unimplemented_methods:
            useragent = request.getHeader("user-agent")
            if not useragent:
                useragent = "<not supplied>"

            logtype = self.factory.logger.LOG_HTTP_UNIMPLEMENTED_METHOD
            logdata = {
                "SKIN": self.skin,
                "HOSTNAME": request.getRequestHostname(),
                "PATH": request.path,
                "USERAGENT": useragent,
                "REQUEST_TYPE": request.method,
            }
            self.factory.log(logdata, transport=request.transport, logtype=logtype)


class RedirectCustomHeaders(Redirect):
    def __init__(self, request, factory):
        Redirect.__init__(self, request)
        self.factory = factory
        self.skin = self.factory.skin
        self.skindir = self.factory.skindir

    def render(self, request):
        if self.factory.config.getVal("http.log_redirect_request", default=False):
            useragent = request.getHeader("user-agent")
            if not useragent:
                useragent = "<not supplied>"

            logtype = self.factory.logger.LOG_HTTP_REDIRECT

            logdata = {
                "HOSTNAME": request.getRequestHostname(),
                "PATH": request.path,
                "USERAGENT": useragent,
            }

            self.factory.log(logdata, transport=request.transport, logtype=logtype)

        request.setHeader(b"Server", self.factory.banner)
        return self._redirect_to(request)

    def _redirect_to(self, request):
        if not isinstance(self.url, bytes):
            raise TypeError("URL must be bytes")
        request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
        request.redirect(self.url)

        content = self._get_redirect_file_content()
        return content

    def _get_redirect_file_content(self):
        if not os.path.isdir(self.skindir):
            raise Exception(
                "Directory %s for http skin, %s, does not exist."
                % (self.factory.skindir, self.skin)
            )

        with open(os.path.join(self.skindir, "redirect.html")) as f:
            text = f.read()

        return bytes(text, "utf-8")


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
        request.setHeader("Server", StaticNoDirListing.BANNER)
        return static.File.getChild(self, name, request)


class CanaryHTTP(CanaryService):
    NAME = "http"

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.skin = config.getVal("http.skin", default="basicLogin")
        self.skindir = config.getVal("http.skindir", default="")
        if not os.path.isdir(self.skindir):
            self.skindir = os.path.join(CanaryHTTP.resource_dir(), "skin", self.skin)
        self.staticdir = os.path.join(self.skindir, "static")
        self.port = int(config.getVal("http.port", default=80))
        ubanner = config.getVal("http.banner", default="Apache/2.2.22 (Ubuntu)")
        self.banner = ubanner.encode("utf8")
        StaticNoDirListing.BANNER = self.banner
        self.listen_addr = config.getVal("device.listen_addr", default="")

    def getService(self):
        page = BasicLogin(factory=self)
        root = StaticNoDirListing(self.staticdir)
        root.createErrorPages(self)
        root.putChild(b"", RedirectCustomHeaders(b"/index.html", factory=self))
        root.putChild(b"index.html", page)
        wrapped = EncodingResourceWrapper(root, [GzipEncoderFactory()])
        site = CanaryHttpServiceSite(wrapped)
        return internet.TCPServer(self.port, site, interface=self.listen_addr)
