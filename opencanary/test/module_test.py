"""
This module assumes that OpenCanary has been installed and is running.

In particular it assumes that OpenCanary is logging to /var/tmp/opencanary.log
and that the services it's testing are enabled.

It would be much better to setup tests to start the services needed and provide
the configuration files so that tests can be run without needing to reinstall
and start the service before each test. It would also be better to be able to
test the code directly rather than relying on the out put of logs.

Still this is a start.
"""

import time
import json
import unittest
import socket
import warnings  # Used in the TestSSHModule (see comment there)

# These libraries are only needed by the test suite and so aren't in the
# OpenCanary requirements, there is a requirements.txt file in the tests folder
# Simply run `pip install -r opencanary/test/requirements.txt`
import requests
import paramiko
import pymysql


def get_last_log():
    """
    Gets the last line from `/var/tmp/opencanary.log` as a dictionary
    """
    return get_last_n_logs(1)[0]


def get_last_n_logs(n):
    """
    Reads the last 'n' lines from a file and returns them as a list of dictionaries.
    """
    with open("/var/tmp/opencanary.log", "r") as file:
        lines = file.readlines()

    last_n_lines = lines[-n:]
    deserialized_data = [json.loads(line) for line in last_n_lines]
    return deserialized_data


class TestHTTPModule(unittest.TestCase):
    """
    Tests the cases for the HTTP module.

    The HTTP server should look like a NAS and present a login box, any
    interaction with the server (GET, POST) should be logged.
    """

    def test_get_http_home_page(self):
        """
        Simply get the home page.
        """
        request = requests.get("http://localhost/")
        self.assertEqual(request.status_code, 200)
        self.assertIn("Synology DiskStation", request.text)
        last_log = get_last_log()
        self.assertEqual(last_log["dst_port"], 80)
        self.assertEqual(last_log["logdata"]["HOSTNAME"], "localhost")
        self.assertEqual(last_log["logdata"]["PATH"], "/index.html")
        self.assertIn("python-requests", last_log["logdata"]["USERAGENT"])

    def test_log_in_to_http_with_basic_auth(self):
        """
        Try to log into the site with basic auth.
        """
        request = requests.post("http://localhost/", auth=("user", "pass"))
        # Currently the web server returns 200, but in future it should return
        # a 403 status code.
        self.assertEqual(request.status_code, 200)
        self.assertIn("Synology DiskStation", request.text)
        last_log = get_last_log()
        self.assertEqual(last_log["dst_port"], 80)
        self.assertEqual(last_log["logdata"]["HOSTNAME"], "localhost")
        self.assertEqual(last_log["logdata"]["PATH"], "/index.html")
        self.assertIn("python-requests", last_log["logdata"]["USERAGENT"])
        # OpenCanary doesn't currently record credentials from basic auth.

    def test_log_in_to_http_with_parameters(self):
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
        self.assertEqual(request.status_code, 200)
        self.assertIn("Synology DiskStation", request.text)
        last_log = get_last_log()
        self.assertEqual(last_log["dst_port"], 80)
        self.assertEqual(last_log["logdata"]["HOSTNAME"], "localhost")
        self.assertEqual(last_log["logdata"]["PATH"], "/index.html")
        self.assertIn("python-requests", last_log["logdata"]["USERAGENT"])
        self.assertEqual(last_log["logdata"]["USERNAME"], "test_user")
        self.assertEqual(last_log["logdata"]["PASSWORD"], "test_pass")

    def test_get_directory_listing(self):
        """
        Try to get a directory listing should result in a 403 Forbidden message.
        """
        request = requests.get("http://localhost/css/")
        self.assertEqual(request.status_code, 403)
        self.assertIn("Forbidden", request.text)
        # These request are not logged at the moment. Maybe we should.

    def test_get_non_existent_file(self):
        """
        Try to get a file that doesn't exist should give a 404 error message.
        """
        request = requests.get("http://localhost/this/file/doesnt_exist.txt")
        self.assertEqual(request.status_code, 404)
        self.assertIn("Not Found", request.text)
        # These request are not logged at the moment. Maybe we should.

    def test_get_supporting_image_file(self):
        """
        Try to download a supporting image file
        """
        request = requests.get(
            "http://localhost/img/synohdpack/images/Components/checkbox.png"
        )
        # Just an arbitrary image
        self.assertEqual(request.status_code, 200)

    def test_unimplemented_delete_http_method(self):
        """
        Try sending a request with an unimplemented HTTP type (DELETE)
        """
        request = requests.delete("http://localhost/index.html")
        last_log = get_last_log()
        self.assertEqual(last_log["logtype"], 3002)
        self.assertEqual(last_log["logdata"]["REQUEST_TYPE"], "DELETE")
        self.assertEqual(request.status_code, 405)

    def test_unimplemented_patch_http_method(self):
        """
        Try sending a request with an unimplemented HTTP type (PATCH)
        """
        request = requests.patch("http://localhost/index.html", {})
        last_log = get_last_log()
        self.assertEqual(last_log["logtype"], 3002)
        self.assertEqual(last_log["logdata"]["REQUEST_TYPE"], "PATCH")
        self.assertEqual(request.status_code, 405)

    def test_unimplemented_put_http_method(self):
        """
        Try sending a request with an unimplemented HTTP type (PUT)
        """
        request = requests.put("http://localhost/index.html")
        last_log = get_last_log()
        self.assertEqual(last_log["logtype"], 3002)
        self.assertEqual(last_log["logdata"]["REQUEST_TYPE"], "PUT")
        self.assertEqual(request.status_code, 405)

    def test_unimplemented_connect_http_method(self):
        """
        Try sending a request with an unimplemented HTTP type (CONNECT)
        """
        request = requests.request("CONNECT", "http://localhost/index.html")
        last_log = get_last_log()
        self.assertEqual(last_log["logtype"], 3002)
        self.assertEqual(last_log["logdata"]["REQUEST_TYPE"], "CONNECT")
        self.assertEqual(request.status_code, 405)

    def test_unimplemented_trace_http_method(self):
        """
        Try sending a request with an unimplemented HTTP type (TRACE)
        """
        request = requests.request("TRACE", "http://localhost/index.html")
        last_log = get_last_log()
        self.assertEqual(last_log["logtype"], 3002)
        self.assertEqual(last_log["logdata"]["REQUEST_TYPE"], "TRACE")
        self.assertEqual(request.status_code, 405)

    def test_unimplemented_head_http_method(self):
        """
        Try sending a request with an unimplemented HTTP type (HEAD)
        """
        request = requests.head("http://localhost/index.html")
        last_log = get_last_log()
        self.assertEqual(last_log["logtype"], 3002)
        self.assertEqual(last_log["logdata"]["REQUEST_TYPE"], "HEAD")
        self.assertEqual(request.status_code, 405)

    def test_invalid_http_request(self):
        """
        Try sending a request with an invalid HTTP verb
        """
        request = requests.request("INVALID", "http://localhost/index.html")
        self.assertEqual(request.status_code, 405)

    def test_redirect(self):
        """
        Send a POST request to root to receive redirect.
        """
        request = requests.post("http://localhost", allow_redirects=False)
        last_log = get_last_log()
        self.assertEqual(request.status_code, 302)
        self.assertEqual(last_log["logtype"], 3003)


class TestHTTPSModule(unittest.TestCase):
    """
    Tests the cases for the HTTP module.

    The HTTP server should look like a NAS and present a login box, any
    interaction with the server (GET, POST) should be logged.
    """

    def test_get_http_home_page(self):
        """
        Simply get the home page.
        """
        request = requests.get("https://localhost/", verify=False)
        self.assertEqual(request.status_code, 200)
        self.assertIn("Synology DiskStation", request.text)
        last_log = get_last_log()
        self.assertEqual(last_log["dst_port"], 443)
        self.assertEqual(last_log["logdata"]["HOSTNAME"], "localhost")
        self.assertEqual(last_log["logdata"]["PATH"], "/index.html")
        self.assertIn("python-requests", last_log["logdata"]["USERAGENT"])

    def test_log_in_to_http_with_basic_auth(self):
        """
        Try to log into the site with basic auth.
        """
        request = requests.post(
            "https://localhost/", auth=("user", "pass"), verify=False
        )
        # Currently the web server returns 200, but in future it should return
        # a 403 status code.
        self.assertEqual(request.status_code, 200)
        self.assertIn("Synology DiskStation", request.text)
        last_log = get_last_log()
        self.assertEqual(last_log["dst_port"], 443)
        self.assertEqual(last_log["logdata"]["HOSTNAME"], "localhost")
        self.assertEqual(last_log["logdata"]["PATH"], "/index.html")
        self.assertIn("python-requests", last_log["logdata"]["USERAGENT"])
        # OpenCanary doesn't currently record credentials from basic auth.

    def test_log_in_to_http_with_parameters(self):
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
        self.assertEqual(request.status_code, 200)
        self.assertIn("Synology DiskStation", request.text)
        last_log = get_last_log()
        self.assertEqual(last_log["dst_port"], 443)
        self.assertEqual(last_log["logdata"]["HOSTNAME"], "localhost")
        self.assertEqual(last_log["logdata"]["PATH"], "/index.html")
        self.assertIn("python-requests", last_log["logdata"]["USERAGENT"])
        self.assertEqual(last_log["logdata"]["USERNAME"], "test_user")
        self.assertEqual(last_log["logdata"]["PASSWORD"], "test_pass")

    def test_get_directory_listing(self):
        """
        Try to get a directory listing should result in a 403 Forbidden message.
        """
        request = requests.get("https://localhost/css/", verify=False)
        self.assertEqual(request.status_code, 403)
        self.assertIn("Forbidden", request.text)
        # These request are not logged at the moment. Maybe we should.

    def test_get_non_existent_file(self):
        """
        Try to get a file that doesn't exist should give a 404 error message.
        """
        request = requests.get(
            "https://localhost/this/file/doesnt_exist.txt", verify=False
        )
        self.assertEqual(request.status_code, 404)
        self.assertIn("Not Found", request.text)
        # These request are not logged at the moment. Maybe we should.

    def test_get_supporting_image_file(self):
        """
        Try to download a supporting image file
        """
        request = requests.get(
            "https://localhost/img/synohdpack/images/Components/checkbox.png",
            verify=False,
        )
        # Just an arbitrary image
        self.assertEqual(request.status_code, 200)


class TestSSHModule(unittest.TestCase):
    """
    Tests the cases for the SSH server
    """

    def setUp(self):
        self.connection = paramiko.SSHClient()
        self.connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def test_ssh_with_basic_login(self):
        """
        Try to log into the SSH server
        """
        # FIXME: At the time of this writing, paramiko calls cryptography
        # which throws a depreciation warning. It looks like this has been
        # fixed https://github.com/paramiko/paramiko/issues/1369 but the fix
        # hasn't been pushed to pypi. When the fix is pushed we can update
        # and remove the import warnings and the warnings.catch.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.assertRaises(
                paramiko.ssh_exception.AuthenticationException,
                self.connection.connect,
                hostname="localhost",
                port=2222,
                username="test_user",
                password="test_pass",
            )
        last_log = get_last_log()
        self.assertEqual(last_log["dst_port"], 2222)
        self.assertIn("paramiko", last_log["logdata"]["REMOTEVERSION"])
        self.assertEqual(last_log["logdata"]["USERNAME"], "test_user")
        self.assertEqual(last_log["logdata"]["PASSWORD"], "test_pass")

    def tearDown(self):
        self.connection.close()


class TestMySQLModule(unittest.TestCase):
    """
    Tests the MySQL Server attempting to login should fail and
    """

    def test_mysql_server_login(self):
        """
        Login to the mysql server
        """
        self.assertRaises(
            pymysql.err.OperationalError,
            pymysql.connect,
            host="localhost",
            user="test_user",
            password="test_pass",
            db="db",
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
        )
        last_log = get_last_log()
        self.assertEqual(last_log["logdata"]["USERNAME"], "test_user")
        #        self.assertEqual(last_log['logdata']['PASSWORD'], "b2e5ed6a0e59f99327399ced2009338d5c0fe237")
        self.assertEqual(last_log["dst_port"], 3306)

    def test_attempted_mysql_login(self):
        """
        Try to connect to the FTP service should log the connection attempt.
        """
        self.assertRaises(
            pymysql.err.OperationalError,
            pymysql.connect,
            host="localhost",
            user="anyone",
            password="AsDAS9d103294",
            db="invaliddb",
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
        )
        log = get_last_n_logs(2)[0]
        self.assertEqual(log["logtype"], 9003)
        self.assertEqual(log["dst_port"], 3306)
        self.assertEqual(log["logdata"], {})


class TestRDPModule(unittest.TestCase):
    """
    Tests the RDP Server
    """

    def test_rdp_with_user_cookie(self):
        """
        Login to the RDP server and pass the username in the connection request
        """
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect(("localhost", 3389))
        packet = b""
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3
        # TPKT details
        packet += b"\x03\x00\x00\x33"
        # ISO connection
        packet += b"\x2e\xe0\x00\x00\x00\x00\x00"
        # RDP Cookie
        packet += b"Cookie: mstshash=test_rdp_user"
        # Negotiation request
        packet += b"\x01\x00\x08\x00\x03\x00\x00\x00"
        self.connection.sendall(packet)
        time.sleep(1)

        last_log = get_last_log()
        self.assertEqual(last_log["logdata"]["USERNAME"], "test_rdp_user")
        self.assertEqual(last_log["dst_port"], 3389)

    def test_rdp_connection_with_no_user_details(self):
        """
        Connect to the RDP server, but do not pass a username (e.g. namp scan)
        """
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect(("localhost", 3389))
        packet = b""
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3
        # TPKT details
        packet += b"\x03\x00\x00\x13"
        # ISO connection
        packet += b"\x0e\xe0\x00\x00\x00\x00\x01"
        # Negotiation request
        packet += b"\x01\x00\x08\x00\x03\x00\x00\x00"
        self.connection.sendall(packet)
        time.sleep(1)

        last_log = get_last_log()
        self.assertEqual(last_log["logdata"]["USERNAME"], None)
        self.assertEqual(last_log["dst_port"], 3389)


if __name__ == "__main__":
    unittest.main()
