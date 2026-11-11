"""
Tests the cases for the HTTPS module.

The HTTPS server should look like a NAS and present a login box, any
interaction with the server (GET, POST) should be logged.
"""

import pytest
import requests

pytestmark = pytest.mark.filterwarnings(
    "ignore:Unverified HTTPS request is being made to host.*:urllib3.exceptions.InsecureRequestWarning"
)


@pytest.fixture
def https_server(canary):
    return canary("https")


def get_page_log(server, start):
    log = server.get_matching_log(
        start,
        lambda entry: entry.get("logdata", {}).get("PATH") == "/index.html",
    )
    assert log is not None
    return log


def test_get_https_home_page(https_server):
    """
    Simply get the home page.
    """
    start = https_server.get_log_count()
    request = requests.get(f"{https_server.url}/", verify=False, timeout=5)
    assert request.status_code == 200
    assert "Synology DiskStation" in request.text
    last_log = get_page_log(https_server, start)
    assert last_log["dst_port"] == https_server.port
    assert last_log["logdata"]["HOSTNAME"] == https_server.host
    assert last_log["logdata"]["PATH"] == "/index.html"
    assert "python-requests" in last_log["logdata"]["USERAGENT"]


def test_log_in_to_https_with_basic_auth(https_server):
    """
    Try to log into the site with basic auth.
    """
    start = https_server.get_log_count()
    request = requests.post(
        f"{https_server.url}/", auth=("user", "pass"), verify=False, timeout=5
    )
    # Currently the web server returns 200, but in future it should return
    # a 403 status code.
    assert request.status_code == 200
    assert "Synology DiskStation" in request.text
    last_log = get_page_log(https_server, start)
    assert last_log["dst_port"] == https_server.port
    assert last_log["logdata"]["HOSTNAME"] == https_server.host
    assert last_log["logdata"]["PATH"] == "/index.html"
    assert "python-requests" in last_log["logdata"]["USERAGENT"]
    # OpenCanary doesn't currently record credentials from basic auth.


def test_log_in_to_https_with_parameters(https_server):
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
    start = https_server.get_log_count()
    request = requests.post(
        f"{https_server.url}/index.html", data=login_data, verify=False, timeout=5
    )
    # Currently the web server returns 200, but in future it should return
    # a 403 status code.
    assert request.status_code == 200
    assert "Synology DiskStation" in request.text
    last_log = get_page_log(https_server, start)
    assert last_log["dst_port"] == https_server.port
    assert last_log["logdata"]["HOSTNAME"] == https_server.host
    assert last_log["logdata"]["PATH"] == "/index.html"
    assert "python-requests" in last_log["logdata"]["USERAGENT"]
    assert last_log["logdata"]["USERNAME"] == "test_user"
    assert last_log["logdata"]["PASSWORD"] == "test_pass"


def test_get_directory_listing(https_server):
    """
    Try to get a directory listing should result in a 403 Forbidden message.
    """
    request = requests.get(f"{https_server.url}/css/", verify=False, timeout=5)
    assert request.status_code == 403
    assert "Forbidden" in request.text
    # These request are not logged at the moment. Maybe we should.


def test_get_non_existent_file(https_server):
    """
    Try to get a file that doesn't exist should give a 404 error message.
    """
    request = requests.get(
        f"{https_server.url}/this/file/doesnt_exist.txt", verify=False, timeout=5
    )
    assert request.status_code == 404
    assert "Not Found" in request.text
    # These request are not logged at the moment. Maybe we should.


def test_get_supporting_image_file(https_server):
    """
    Try to download a supporting image file
    """
    request = requests.get(
        f"{https_server.url}/img/synohdpack/images/Components/checkbox.png",
        verify=False,
        timeout=5,
    )
    # Just an arbitrary image
    assert request.status_code == 200
