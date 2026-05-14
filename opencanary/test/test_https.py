"""
Tests the cases for the HTTPS module.

The HTTPS server should look like a NAS and present a login box, any
interaction with the server (GET, POST) should be logged.
"""

import pytest
import requests

from helpers import get_last_log

pytestmark = pytest.mark.filterwarnings(
    "ignore:Unverified HTTPS request is being made to host.*:urllib3.exceptions.InsecureRequestWarning"
)


def test_get_https_home_page():
    """
    Simply get the home page.
    """
    request = requests.get("https://localhost/", verify=False)
    assert request.status_code == 200
    assert "Synology DiskStation" in request.text
    last_log = get_last_log()
    assert last_log["dst_port"] == 443
    assert last_log["logdata"]["HOSTNAME"] == "localhost"
    assert last_log["logdata"]["PATH"] == "/index.html"
    assert "python-requests" in last_log["logdata"]["USERAGENT"]


def test_log_in_to_https_with_basic_auth():
    """
    Try to log into the site with basic auth.
    """
    request = requests.post("https://localhost/", auth=("user", "pass"), verify=False)
    # Currently the web server returns 200, but in future it should return
    # a 403 status code.
    assert request.status_code == 200
    assert "Synology DiskStation" in request.text
    last_log = get_last_log()
    assert last_log["dst_port"] == 443
    assert last_log["logdata"]["HOSTNAME"] == "localhost"
    assert last_log["logdata"]["PATH"] == "/index.html"
    assert "python-requests" in last_log["logdata"]["USERAGENT"]
    # OpenCanary doesn't currently record credentials from basic auth.


def test_log_in_to_https_with_parameters():
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
    request = requests.post(
        "https://localhost/index.html", data=login_data, verify=False
    )
    # Currently the web server returns 200, but in future it should return
    # a 403 status code.
    assert request.status_code == 200
    assert "Synology DiskStation" in request.text
    last_log = get_last_log()
    assert last_log["dst_port"] == 443
    assert last_log["logdata"]["HOSTNAME"] == "localhost"
    assert last_log["logdata"]["PATH"] == "/index.html"
    assert "python-requests" in last_log["logdata"]["USERAGENT"]
    assert last_log["logdata"]["USERNAME"] == "test_user"
    assert last_log["logdata"]["PASSWORD"] == "test_pass"


def test_get_directory_listing():
    """
    Try to get a directory listing should result in a 403 Forbidden message.
    """
    request = requests.get("https://localhost/css/", verify=False)
    assert request.status_code == 403
    assert "Forbidden" in request.text
    # These request are not logged at the moment. Maybe we should.


def test_get_non_existent_file():
    """
    Try to get a file that doesn't exist should give a 404 error message.
    """
    request = requests.get("https://localhost/this/file/doesnt_exist.txt", verify=False)
    assert request.status_code == 404
    assert "Not Found" in request.text
    # These request are not logged at the moment. Maybe we should.


def test_get_supporting_image_file():
    """
    Try to download a supporting image file
    """
    request = requests.get(
        "https://localhost/img/synohdpack/images/Components/checkbox.png",
        verify=False,
    )
    # Just an arbitrary image
    assert request.status_code == 200
