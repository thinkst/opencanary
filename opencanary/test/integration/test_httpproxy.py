import base64

import pytest
import requests

from opencanary.logger import LoggerBase


@pytest.mark.parametrize(
    "scheme,credentials",
    [("Basic", b"test_user:test_pass"), ("NTLM", b"TlRMTVNTUAABAAAA")],
)
def test_httpproxy_auth_attempt_is_logged(canary, scheme, credentials):
    # NTLM previously exited before logging the attempt.
    service = canary("httpproxy")
    start = service.get_log_count()
    token = base64.b64encode(credentials).decode("ascii")

    with requests.Session() as session:
        session.trust_env = False
        response = session.get(
            "http://example.com/",
            proxies={"http": f"http://{service.host}:{service.port}"},
            headers={"Proxy-Authorization": f"{scheme} {token}"},
            timeout=5,
        )
    assert response.status_code == 407

    log = service.get_matching_log(
        start,
        lambda event: event.get("logtype") == LoggerBase.LOG_HTTPPROXY_LOGIN_ATTEMPT
        and event.get("dst_port") == service.port
        and "USERNAME" in event.get("logdata", {})
        and "PASSWORD" in event.get("logdata", {}),
    )
    assert log is not None
    if scheme == "Basic":
        assert log["logdata"]["USERNAME"] == "test_user"
        assert log["logdata"]["PASSWORD"] == "test_pass"
