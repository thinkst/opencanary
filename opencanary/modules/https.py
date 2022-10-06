import os
import re
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from twisted.application import internet
from twisted.web import static
from twisted.web.resource import Resource, EncodingResourceWrapper
from twisted.web.server import Site, GzipEncoderFactory
from twisted.web.util import Redirect
from twisted.internet.ssl import DefaultOpenSSLContextFactory

from opencanary.modules import CanaryService


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


class BasicLogin(Resource):
    isLeaf = True

    def __init__(self, factory):
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

    def render_GET(self, request, loginFailed=False):
        if not loginFailed:
            us = request.transport.getHost()
            peer = request.transport.getPeer()
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


class RedirectCustomHeaders(Redirect):
    def __init__(self, request, factory):
        Redirect.__init__(self, request)
        self.factory = factory

    def render(self, request):
        request.setHeader(b"Server", self.factory.banner)
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
        request.setHeader("Server", StaticNoDirListing.BANNER)
        return static.File.getChild(self, name, request)


class CanaryHTTPS(CanaryService):
    NAME = "https"

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.skin = config.getVal("https.skin", default="basicLogin")
        self.skindir = config.getVal("https.skindir", default="")
        if not os.path.isdir(self.skindir):
            self.skindir = os.path.join(CanaryHTTPS.resource_dir(), "skin", self.skin)
        self.staticdir = os.path.join(self.skindir, "static")
        self.port = int(config.getVal("https.port", default=443))
        ubanner = config.getVal("http.banner", default="Apache/2.2.22 (Ubuntu)")
        self.banner = ubanner.encode("utf8")
        StaticNoDirListing.BANNER = self.banner
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.domain_name = config.getVal(
            "https.domain_name", default="synologynas.local"
        )
        self.certificate_path = Path(
            config.getVal(
                "https.certificate", default="/etc/ssl/opencanary/opencanary.pem"
            )
        )
        self.key_path = Path(
            config.getVal("https.key", default="/etc/ssl/opencanary/opencanary.key")
        )

    def load_certificates(self):
        """
        If certificates already exist, use them, otherwise we generate self signed certificates.
        """
        if self.certificate_path.exists() and self.key_path.exists():
            pass
        else:
            # Make the directory to save the keys into (if it doesn't already exist)
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            self.certificate_path.parent.mkdir(parents=True, exist_ok=True)

            # Generate our Key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            # Write our key to disk for safe keeping
            with open(self.key_path, "wb") as key_file:
                key_file.write(
                    key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=None,
                    )
                )
            # Various details about who we are. For a self-signed certificate the
            # subject and issuer are always the same.
            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Synology Inc. CA"),
                    x509.NameAttribute(NameOID.COMMON_NAME, self.domain_name),
                ]
            )
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=365))
                .sign(key, hashes.SHA256())
            )
            # Write our certificate out to disk.
            with open(self.certificate_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))


def getService(self):
    page = BasicLogin(factory=self)
    root = StaticNoDirListing(self.staticdir)
    root.createErrorPages(self)
    root.putChild(b"", RedirectCustomHeaders(b"/index.html", factory=self))
    root.putChild(b"index.html", page)
    wrapped = EncodingResourceWrapper(root, [GzipEncoderFactory()])
    site = Site(wrapped)
    return internet.SSLServer(
        self.port,
        site,
        DefaultOpenSSLContextFactory(
            privateKeyFileName=self.key,
            certificateFileName=self.certificate,
        ),
        interface=self.listen_addr,
    )
