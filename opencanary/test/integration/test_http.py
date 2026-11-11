"""
Tests the cases for the HTTP module.

The HTTP server should look like a NAS and present a login box, any
interaction with the server (GET, POST) should be logged.
"""

import requests
import pytest


@pytest.fixture
def http_server(canary):
    return canary("http")


def get_page_log(server, start):
    log = server.get_matching_log(
        start,
        lambda entry: entry.get("logdata", {}).get("PATH") == "/index.html",
    )
    assert log is not None
    return log


def test_get_http_home_page(http_server):
    """
    Simply get the home page.
    """
    start = http_server.get_log_count()
    request = requests.get(f"{http_server.url}/", timeout=5)
    assert request.status_code == 200
    assert "Synology DiskStation" in request.text
    last_log = get_page_log(http_server, start)
    assert last_log["dst_port"] == http_server.port
    assert last_log["logdata"]["HOSTNAME"] == http_server.host
    assert last_log["logdata"]["PATH"] == "/index.html"
    assert "python-requests" in last_log["logdata"]["USERAGENT"]


def test_log_in_to_http_with_basic_auth(http_server):
    """
    Try to log into the site with basic auth.
    """
    start = http_server.get_log_count()
    request = requests.post(f"{http_server.url}/", auth=("user", "pass"), timeout=5)
    # Currently the web server returns 200, but in future it should return
    # a 403 status code.
    assert request.status_code == 200
    assert "Synology DiskStation" in request.text
    last_log = get_page_log(http_server, start)
    assert last_log["dst_port"] == http_server.port
    assert last_log["logdata"]["HOSTNAME"] == http_server.host
    assert last_log["logdata"]["PATH"] == "/index.html"
    assert "python-requests" in last_log["logdata"]["USERAGENT"]
    # OpenCanary doesn't currently record credentials from basic auth.


def test_log_in_to_http_with_parameters(http_server):
    """
    Try to log into the site by posting the parameters
    """
    login_data = {
        "username": "test_user",
        "password": "test_pass",
        "OTPcode": "",
        "rememberme": "",
        "__cIpHeRtExt": "",
        "isIframeLogin": "yes",
    }
    start = http_server.get_log_count()
    request = requests.post(f"{http_server.url}/index.html", data=login_data, timeout=5)
    # Currently the web server returns 200, but in future it should return
    # a 403 status code.
    assert request.status_code == 200
    assert "Synology DiskStation" in request.text
    last_log = get_page_log(http_server, start)
    assert last_log["dst_port"] == http_server.port
    assert last_log["logdata"]["HOSTNAME"] == http_server.host
    assert last_log["logdata"]["PATH"] == "/index.html"
    assert "python-requests" in last_log["logdata"]["USERAGENT"]
    assert last_log["logdata"]["USERNAME"] == "test_user"
    assert last_log["logdata"]["PASSWORD"] == "test_pass"


def test_get_directory_listing(http_server):
    """
    Try to get a directory listing should result in a 403 Forbidden message.
    """
    request = requests.get(f"{http_server.url}/css/", timeout=5)
    assert request.status_code == 403
    assert "Forbidden" in request.text
    # These request are not logged at the moment. Maybe we should.


def test_get_non_existent_file(http_server):
    """
    Try to get a file that doesn't exist should give a 404 error message.
    """
    request = requests.get(f"{http_server.url}/this/file/doesnt_exist.txt", timeout=5)
    assert request.status_code == 404
    assert "Not Found" in request.text
    # These request are not logged at the moment. Maybe we should.


def test_get_supporting_image_file(http_server):
    """
    Try to download a supporting image file
    """
    request = requests.get(
        f"{http_server.url}/img/synohdpack/images/Components/checkbox.png",
        timeout=5,
    )
    # Just an arbitrary image
    assert request.status_code == 200


@pytest.mark.parametrize(
    "request_type, request_kwargs",
    [
        pytest.param("DELETE", {}, id="delete"),
        pytest.param("PATCH", {"json": {}}, id="patch"),
        pytest.param("PUT", {}, id="put"),
        pytest.param("CONNECT", {}, id="connect"),
        pytest.param("TRACE", {}, id="trace"),
        pytest.param("HEAD", {}, id="head"),
    ],
)
def test_unimplemented_http_methods(http_server, request_type, request_kwargs):
    """
    Try sending requests with unimplemented HTTP types.
    """
    start = http_server.get_log_count()
    request = requests.request(
        request_type, f"{http_server.url}/index.html", timeout=5, **request_kwargs
    )
    last_log = http_server.get_matching_log(
        start,
        lambda entry: (
            entry.get("logtype") == 3002
            and entry.get("logdata", {}).get("REQUEST_TYPE") == request_type
        ),
    )
    assert last_log is not None
    assert last_log["logtype"] == 3002
    assert last_log["logdata"]["REQUEST_TYPE"] == request_type
    assert request.status_code == 405


def test_invalid_http_request(http_server):
    """
    Try sending a request with an invalid HTTP verb
    """
    request = requests.request("INVALID", f"{http_server.url}/index.html", timeout=5)
    assert request.status_code == 405


def test_redirect(http_server):
    """
    Send a POST request to root to receive redirect.
    """
    start = http_server.get_log_count()
    request = requests.post(http_server.url, allow_redirects=False, timeout=5)
    last_log = http_server.get_matching_log(
        start, lambda entry: entry.get("logtype") == 3003
    )
    assert last_log is not None
    assert request.status_code == 302
    assert last_log["logtype"] == 3003
