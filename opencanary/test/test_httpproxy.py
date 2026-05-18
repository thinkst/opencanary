import base64

import requests

from helpers import get_log_count, get_matching_log
from opencanary.logger import LoggerBase

HTTPPROXY_PORT = 8080


def get_httpproxy_log(start_line):
    def is_matching_log(log):
        if log.get("logtype") != LoggerBase.LOG_HTTPPROXY_LOGIN_ATTEMPT:
            return False
        if log.get("dst_port") != HTTPPROXY_PORT:
            return False
        if "USERNAME" not in log.get("logdata", {}):
            return False
        if "PASSWORD" not in log.get("logdata", {}):
            return False
        return True

    return get_matching_log(start_line, is_matching_log)


def test_httpproxy_auth_attempt_is_logged():
    """
    Send a proxy request with auth and verify it is logged.
    """
    log_start = get_log_count()
    token = base64.b64encode(b"test_user:test_pass").decode("ascii")

    session = requests.Session()
    session.trust_env = False
    response = session.get(
        "http://example.com/",
        proxies={"http": f"http://localhost:{HTTPPROXY_PORT}"},
        headers={"Proxy-Authorization": f"Basic {token}"},
        timeout=2,
    )

    assert response.status_code == 407

    log = get_httpproxy_log(log_start)
    assert log is not None
    assert log["dst_port"] == HTTPPROXY_PORT
    assert log["logtype"] == LoggerBase.LOG_HTTPPROXY_LOGIN_ATTEMPT
    assert "USERNAME" in log["logdata"]
    assert "PASSWORD" in log["logdata"]
