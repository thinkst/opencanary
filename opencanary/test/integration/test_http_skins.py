"""
The root redirect must work for skins that do not ship a redirect.html.

basicLogin (the default skin) only provides index/403/404 pages; the
redirect response must still carry a followable link to the login page
so the visit is logged instead of failing with a 500.
"""

import re

import requests


def test_root_redirect_without_skin_redirect_file(canary):
    """
    Follow the fallback link from the root redirect body of a skin
    without redirect.html and check the login page is served and logged.
    """
    server = canary("http", overrides={"http.skin": "basicLogin"})
    start = server.get_log_count()
    redirect = requests.get(server.url, allow_redirects=False, timeout=5)
    assert redirect.status_code == 302
    match = re.search(r'href="([^"]+)"', redirect.text)
    assert match is not None
    target = match.group(1)
    assert redirect.headers["Location"] == target
    page = requests.get(f"{server.url}{target}", timeout=5)
    assert page.status_code == 200
    last_log = server.get_matching_log(
        start,
        lambda entry: (
            entry.get("logtype") == 3000
            and entry.get("logdata", {}).get("PATH") == target
        ),
    )
    assert last_log is not None
