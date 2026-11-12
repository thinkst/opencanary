from email.parser import BytesParser
from html.parser import HTMLParser
from unittest.mock import Mock

import pytest
from twisted.internet.error import ConnectionDone
from twisted.internet.testing import StringTransport
from twisted.python.failure import Failure

from opencanary.logger import LoggerBase
from opencanary.modules.httpproxy import AlertProxyRequest, HTTPProxy


class ProxyPageParser(HTMLParser):
    def __init__(self, body):
        super().__init__(convert_charrefs=True)
        self.elements = []
        self.text = []
        self.feed(body.decode("utf-8"))

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, attrs))

    def handle_data(self, data):
        self.text.append(data)


@pytest.fixture
def proxy_response(monkeypatch):
    config = Mock()
    config.getVal.side_effect = lambda key, default=None: default
    logger = Mock(spec=["log", "LOG_HTTPPROXY_LOGIN_ATTEMPT"])
    logger.LOG_HTTPPROXY_LOGIN_ATTEMPT = LoggerBase.LOG_HTTPPROXY_LOGIN_ATTEMPT
    service = HTTPProxy(config=config, logger=logger)
    monkeypatch.setattr(AlertProxyRequest, "FACTORY", service)
    factory = service.getService().args[1]

    def request(target):
        channel = factory.buildProtocol(None)
        transport = StringTransport()
        channel.makeConnection(transport)
        try:
            channel.dataReceived(
                b"GET " + target.encode("ascii") + b" HTTP/1.1\r\n"
                b"Host: localhost\r\nConnection: close\r\n\r\n"
            )
            head, body = transport.value().split(b"\r\n\r\n", 1)
            status, raw_headers = head.split(b"\r\n", 1)
            headers = BytesParser().parsebytes(raw_headers)
            assert status.startswith(b"HTTP/1.1 407 ")
            assert int(headers["Content-Length"]) == len(body)
            return body
        finally:
            channel.connectionLost(Failure(ConnectionDone()))

    return request


@pytest.mark.parametrize(
    "suffix,escaped",
    [
        (
            '"><script>alert(1)</script>',
            "&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;",
        ),
        ('"', "&#34;"),
        ("'", "&#39;"),
        ("<", "&lt;"),
        (">", "&gt;"),
        ("&", "&amp;"),
    ],
)
def test_proxy_url_is_escaped_in_attributes_and_text(proxy_response, suffix, escaped):
    url = "http://example.com/" + suffix
    body = proxy_response(url)
    page = ProxyPageParser(body)
    baseline = ProxyPageParser(proxy_response("http://example.com/"))
    assert [tag for tag, _ in page.elements] == [tag for tag, _ in baseline.elements]
    assert any(tag == "a" and attrs == [("href", url)] for tag, attrs in page.elements)
    assert "".join(page.text).count(url) == 2
    assert ("http://example.com/" + escaped).encode() in body
    assert b"<script>" not in body


def test_proxy_query_string_is_not_double_escaped(proxy_response):
    url = "http://example.com/?a=1&b=2"
    body = proxy_response(url)
    page = ProxyPageParser(body)
    assert b"?a=1&amp;b=2" in body
    assert b"&amp;amp;" not in body
    assert ("a", [("href", url)]) in page.elements


@pytest.mark.parametrize(
    "target",
    [
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "//example.com/path",
        '/"><script>alert(1)</script>',
        "http://[invalid",
        "example.com:443",
    ],
)
def test_proxy_unsafe_or_nonabsolute_url_is_text_only(proxy_response, target):
    body = proxy_response(target)
    page = ProxyPageParser(body)
    assert "".join(page.text).count(target) == 2
    assert all(
        value.startswith("mailto:")
        for tag, attrs in page.elements
        for name, value in attrs
        if tag == "a" and name == "href"
    )
    assert b"<script>" not in body


@pytest.mark.parametrize("scheme", ["http", "https", "HTTPS"])
def test_proxy_http_urls_remain_clickable(proxy_response, scheme):
    url = scheme + "://example.com/path"
    page = ProxyPageParser(proxy_response(url))
    assert ("a", [("href", url)]) in page.elements
