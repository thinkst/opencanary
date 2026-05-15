"""
Tests the cases for the HTTP module.

The HTTP server should look like a NAS and present a login box, any
interaction with the server (GET, POST) should be logged.
"""

import requests
import pytest

from helpers import get_last_log


def test_get_http_home_page():
    """
    Simply get the home page.
    """
    request = requests.get("http://localhost/")
    assert request.status_code == 200
    assert "Synology DiskStation" in request.text
    last_log = get_last_log()
    assert last_log["dst_port"] == 80
    assert last_log["logdata"]["HOSTNAME"] == "localhost"
    assert last_log["logdata"]["PATH"] == "/index.html"
    assert "python-requests" in last_log["logdata"]["USERAGENT"]


def test_log_in_to_http_with_basic_auth():
    """
    Try to log into the site with basic auth.
    """
    request = requests.post("http://localhost/", auth=("user", "pass"))
    # Currently the web server returns 200, but in future it should return
    # a 403 status code.
    assert request.status_code == 200
    assert "Synology DiskStation" in request.text
    last_log = get_last_log()
    assert last_log["dst_port"] == 80
    assert last_log["logdata"]["HOSTNAME"] == "localhost"
    assert last_log["logdata"]["PATH"] == "/index.html"
    assert "python-requests" in last_log["logdata"]["USERAGENT"]
    # OpenCanary doesn't currently record credentials from basic auth.


def test_log_in_to_http_with_parameters():
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
    request = requests.post("http://localhost/index.html", data=login_data)
    # Currently the web server returns 200, but in future it should return
    # a 403 status code.
    assert request.status_code == 200
    assert "Synology DiskStation" in request.text
    last_log = get_last_log()
    assert last_log["dst_port"] == 80
    assert last_log["logdata"]["HOSTNAME"] == "localhost"
    assert last_log["logdata"]["PATH"] == "/index.html"
    assert "python-requests" in last_log["logdata"]["USERAGENT"]
    assert last_log["logdata"]["USERNAME"] == "test_user"
    assert last_log["logdata"]["PASSWORD"] == "test_pass"


def test_get_directory_listing():
    """
    Try to get a directory listing should result in a 403 Forbidden message.
    """
    request = requests.get("http://localhost/css/")
    assert request.status_code == 403
    assert "Forbidden" in request.text
    # These request are not logged at the moment. Maybe we should.


def test_get_non_existent_file():
    """
    Try to get a file that doesn't exist should give a 404 error message.
    """
    request = requests.get("http://localhost/this/file/doesnt_exist.txt")
    assert request.status_code == 404
    assert "Not Found" in request.text
    # These request are not logged at the moment. Maybe we should.


def test_get_supporting_image_file():
    """
    Try to download a supporting image file
    """
    request = requests.get(
        "http://localhost/img/synohdpack/images/Components/checkbox.png"
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
def test_unimplemented_http_methods(request_type, request_kwargs):
    """
    Try sending requests with unimplemented HTTP types.
    """
    request = requests.request(
        request_type, "http://localhost/index.html", **request_kwargs
    )
    last_log = get_last_log()
    assert last_log["logtype"] == 3002
    assert last_log["logdata"]["REQUEST_TYPE"] == request_type
    assert request.status_code == 405


def test_invalid_http_request():
    """
    Try sending a request with an invalid HTTP verb
    """
    request = requests.request("INVALID", "http://localhost/index.html")
    assert request.status_code == 405


def test_redirect():
    """
    Send a POST request to root to receive redirect.
    """
    request = requests.post("http://localhost", allow_redirects=False)
    last_log = get_last_log()
    assert request.status_code == 302
    assert last_log["logtype"] == 3003
