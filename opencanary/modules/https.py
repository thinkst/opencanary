import os
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from twisted.application import internet
from twisted.web.resource import EncodingResourceWrapper
from twisted.web.server import Site, GzipEncoderFactory
from twisted.internet.ssl import DefaultOpenSSLContextFactory

from opencanary.modules import CanaryService
from opencanary.modules.http import (
    BasicLogin,
    CanaryHTTP,
    RedirectCustomHeaders,
    StaticNoDirListing,
)


class CanaryHTTPS(CanaryService):
    NAME = "https"

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.skin = config.getVal("https.skin", default="basicLogin")
        # We share the skin dir with HTTP rather than duplicate everything
        self.skindir = config.getVal("http.skindir", default="")
        if not os.path.isdir(self.skindir):
            self.skindir = os.path.join(CanaryHTTP.resource_dir(), "skin", self.skin)
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
        self.load_certificates()

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
                        encryption_algorithm=serialization.NoEncryption(),
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
                privateKeyFileName=self.key_path,
                certificateFileName=self.certificate_path,
            ),
            interface=self.listen_addr,
        )
