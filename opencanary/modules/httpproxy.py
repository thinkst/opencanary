import os
import datetime

from opencanary.modules import CanaryService

from base64 import b64decode
import urlparse
from urllib import quote as urlquote
from twisted.application import internet
from twisted.internet.protocol import ServerFactory
from twisted.application.internet import TCPServer
from twisted.internet.protocol import ClientFactory
from twisted.internet import protocol

from twisted.web.http import HTTPClient, Request, HTTPChannel
from twisted.web import http
from twisted.internet import reactor

from jinja2 import Template

PROFILES = {
    "ms-isa" : {
        # p/Microsoft ISA Server Web Proxy/
        # Force HTTP/1.1 reply even when sent HTTP/1.0 (to match the nmap version sig)
        "HTTP1.1_always": True,
        "headers": [
            ("Via", "1.1 localhost"),
            ("Proxy-Authenticate", "Basic"),
            # TODO: more realistict authentication for ISA
            # ("Proxy-Authenticate", "NTLM"),
            # ("Proxy-Authenticate", "Kerberos"),
            # ("Proxy-Authenticate", "Negotiate"),
            ("Pragma", "no-cache"),
            ("Cache-Control", "no-cache"),
        ],
        "status_reason": "Proxy Authentication Required ( The ISA Server requires authorization to fulfill the request. Access to the Web Proxy service is denied.  )"
    },
    "squid" : {
        # p/Squid http proxy/ v/$1/ cpe:/a:squid-cache:squid:$1/
        "banner": 'Squid proxy-caching web server',
        "headers": [
            ("Server", "squid/3.3.8"),
            ("Mime-Version", "1.0"),
            ("Vary", "Accept-Language"),
            ("Via", "1.1 localhost (squid/3.3.8)"),
            ("X-Cache", "MISS from localhost"),
            ("X-Cache-Lookup", "NONE from localhost"), # actually hostname:port
            ("X-Squid-Error", "ERR_CACHE_ACCESS_DENIED 0")
        ],
        "status_reason": "Proxy Authentication Required"
    }
}

class AlertProxyRequest(Request):
    """
    Used by Proxy to implement a simple web proxy.
    """

    FACTORY=None

    def __init__(self, channel, queued):
        Request.__init__(self, channel, queued)

    def logAuth(self):
        auth = self.getHeader("Proxy-Authorization")
        if auth is None:
            return

        factory = AlertProxyRequest.FACTORY

        username, password = "Invalid auth-token submitted", ""
        atype, token  = auth.split(" ")
        if atype == "Basic":
            try:
                username, password = b64decode(token).split(":")
            except:
                pass
        elif atype == "NTLM":
            print b64decode(token).split(":")
            exit(1)
            print "something NTLM"
            return

        logdata = {'USERNAME': username, 'PASSWORD': password}
        factory.log(logdata, transport=self.transport)

    def process(self):
        self.logAuth()

        factory = AlertProxyRequest.FACTORY
        profile = PROFILES[factory.skin]
        content = factory.auth_template.render(
            url=self.uri,
            date=datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S %ZGMT"),
            clientip=self.transport.getPeer().host
        )
        if factory.banner:
            prompt = factory.banner
        else:
            prompt = profile.get("banner","")

        #  for fooling nmap service detection
        if profile.get("HTTP1.1_always", False):
            self.clientproto = "HTTP/1.1"

        # match http-proxy m|^HTTP/1\.[01] \d\d\d .*\r\nServer: [sS]quid/([-.\w+]+)\r\n|s
        self.setResponseCode(407, profile["status_reason"])
        for (name, value) in profile["headers"]:
            self.responseHeaders.addRawHeader(name, value)

        self.responseHeaders.addRawHeader("Content-Type", "text/html")
        self.responseHeaders.addRawHeader("Proxy-Authenticate",
                                           'Basic realm="%s"' % prompt)
        self.responseHeaders.addRawHeader("Content-Length", len(content))

        self.write(content.encode("utf-8"))
        self.finish()

class AlertProxy(HTTPChannel):
    requestFactory = AlertProxyRequest

class HTTPProxyFactory(http.HTTPFactory):
    def buildProtocol(self, addr):
        return AlertProxy()

class HTTPProxy(CanaryService):
    NAME = 'httpproxy'

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal('httpproxy.port', default=8443))
        self.banner = config.getVal('httpproxy.banner', '').encode('utf8')
        self.skin = config.getVal('httpproxy.skin', default='squid')
        self.skindir = os.path.join(
            HTTPProxy.resource_dir(), 'skin', self.skin)
        self.logtype = logger.LOG_HTTPPROXY_LOGIN_ATTEMPT
        self.listen_addr = config.getVal('device.listen_addr', default='')

        authfilename = os.path.join(self.skindir, 'auth.html')
        try:
            with open(authfilename, 'r') as f:
                self.auth_template = Template(f.read())
        except:
            self.auth_template = Template("")


    def getService(self):
        AlertProxyRequest.FACTORY = self
        f = HTTPProxyFactory()
        return internet.TCPServer(self.port, f, interface=self.listen_addr)
