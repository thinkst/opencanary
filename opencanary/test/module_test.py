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
from ftplib import FTP, error_perm
import unittest
import socket
import warnings  # Used in the TestSSHModule (see comment there)

# These libraries are only needed by the test suite and so aren't in the
# OpenCanary requirements, there is a requirements.txt file in the tests folder
# Simply run `pip install -r opencanary/test/requirements.txt`
import requests
import paramiko
import pymysql
import git
from pymongo import MongoClient
from pymongo.errors import OperationFailure

MONGODB_PORT = 27017
MONGODB_VERSION = "4.4.6"
MONGODB_AUTH_FAILED_CODE = 18
MONGODB_UNAUTHORIZED_CODE = 13
MONGODB_CLIENT_OPTIONS = {
    "serverSelectionTimeoutMS": 2000,
    "connectTimeoutMS": 2000,
    "socketTimeoutMS": 2000,
    "directConnection": True,
}


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


def get_log_count():
    with open("/var/tmp/opencanary.log", "r") as file:
        return len(file.readlines())


def get_mongodb_log(action, start_line, logdata=None):
    logdata = logdata or {}
    for _ in range(10):
        for log in reversed(get_logs_after(start_line)):
            if log["dst_port"] != MONGODB_PORT:
                continue
            if log["logdata"].get("action") != action:
                continue
            if not all(log["logdata"].get(k) == v for k, v in logdata.items()):
                continue
            return log
        time.sleep(0.1)

    return None


def get_logs_after(start_line):
    with open("/var/tmp/opencanary.log", "r") as file:
        lines = file.readlines()[start_line:]
    return [json.loads(line) for line in lines]


def get_mongodb_client(uri="mongodb://localhost:27017"):
    return MongoClient(uri, **MONGODB_CLIENT_OPTIONS)


class TestFTPModule(unittest.TestCase):
    """
    Tests the cases for the FTP module.

    The FTP server should not allow logins and should log each attempt.
    """

    def setUp(self):
        self.ftp = FTP("localhost")

    def test_attempted_ftp_connection(self):
        """
        Try to connect to the FTP service should log the connection attempt.
        """
        self.assertRaises(error_perm, self.ftp.login)
        log = get_last_n_logs(2)[0]
        self.assertEqual(log["logtype"], 2001)
        self.assertEqual(log["dst_port"], 21)
        self.assertEqual(log["logdata"], {})

    def test_anonymous_ftp(self):
        """
        Try to connect to the FTP service with no username or password.
        """
        self.assertRaises(error_perm, self.ftp.login)
        log = get_last_log()
        self.assertEqual(log["dst_port"], 21)
        self.assertEqual(log["logdata"]["USERNAME"], "anonymous")
        self.assertEqual(log["logdata"]["PASSWORD"], "anonymous@")

    def test_authenticated_ftp(self):
        """
        Connect to the FTP service with a test username and password.
        """
        self.assertRaises(
            error_perm, self.ftp.login, user="test_user", passwd="test_pass"
        )
        last_log = get_last_log()
        self.assertEqual(last_log["dst_port"], 21)
        self.assertEqual(last_log["logdata"]["USERNAME"], "test_user")
        self.assertEqual(last_log["logdata"]["PASSWORD"], "test_pass")

    def tearDown(self):
        self.ftp.close()


class TestGitModule(unittest.TestCase):
    """
    Tests the Git Module by trying to clone a repository from localhost.
    """

    def setUp(self):
        self.repository = git.Repo

    def test_clone_a_repository(self):
        self.assertRaises(
            git.exc.GitCommandError,
            self.repository.clone_from,
            "git://localhost/test.git",
            "/tmp/git_test",
        )

    def test_log_git_clone(self):
        """
        Check that the git clone attempt was logged
        """
        # This test must be run after the test_clone_a_repository.
        # Unless we add an attempt to clone into this test, or the setup.
        last_log = get_last_log()
        self.assertIn("localhost", last_log["logdata"]["HOST"])
        self.assertEqual(last_log["logdata"]["REPO"], "test.git")


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


class TestNTPModule(unittest.TestCase):
    """
    Tests the NTP server. The server doesn't respond, but it will log attempts
    to trigger the MON_GETLIST_1 NTP commands, which is used for DDOS attacks.
    """

    def setUp(self):
        packet = (
            b"\x17"
            + b"\x00"  # response more version mode
            + b"\x03"  # sequence number
            + b"\x2a"  # implementation (NTPv3)
            + b"\x00"  # request (MON_GETLIST_1)
            + b"\x00"  # error number / number of data items
            + b"\x00"  # item_size  # data
        )
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.sendto(packet, ("localhost", 123))

    def test_ntp_server_monlist(self):
        """
        Check that the MON_GETLIST_1 NTP command was logged correctly
        """
        # The logs take about a second to show up, in other tests this is not
        # an issue, because there are checks that run before looking at the log
        # (e.g. request.status_code == 200 for HTTP) but for NTP we just check
        # the log. A hardcoded time out is a horible solution, but it works.
        time.sleep(1)

        last_log = get_last_log()
        self.assertEqual(last_log["logdata"]["NTP CMD"], "monlist")
        self.assertEqual(last_log["dst_port"], 123)

    def tearDown(self):
        self.sock.close()


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


class TestMongoDBModule(unittest.TestCase):
    """
    Tests the MongoDB server with a real MongoDB client.
    """

    def setUp(self):
        self.log_start = get_log_count()
        self.client = get_mongodb_client()

    def test_mongodb_hello(self):
        """
        Connect to the MongoDB service and send a hello command.
        """
        response = self.client.admin.command("hello")

        self.assertEqual(response["ok"], 1.0)
        self.assertTrue(response["ismaster"])
        self.assertEqual(response["version"], MONGODB_VERSION)

        last_log = get_mongodb_log("mongodb.connection", self.log_start)
        self.assertIsNotNone(last_log)
        self.assertEqual(last_log["logtype"], 20001)
        self.assertEqual(last_log["dst_port"], MONGODB_PORT)
        self.assertEqual(last_log["logdata"]["action"], "mongodb.connection")

    def test_mongodb_auth_attempt(self):
        """
        Try to authenticate to the MongoDB service.
        """
        self.client.close()
        self.client = get_mongodb_client(
            "mongodb://test_user:test_pass@localhost:27017/admin?"
            "authMechanism=SCRAM-SHA-256"
        )

        with self.assertRaises(OperationFailure) as error:
            self.client.admin.command("ping")

        self.assertEqual(error.exception.code, MONGODB_AUTH_FAILED_CODE)
        last_log = get_mongodb_log(
            "mongodb.auth_attempt",
            self.log_start,
            {"username": "test_user", "mechanism": "SCRAM-SHA-256"},
        )
        self.assertIsNotNone(last_log)
        self.assertEqual(last_log["logtype"], 20001)
        self.assertEqual(last_log["dst_port"], MONGODB_PORT)
        self.assertEqual(last_log["logdata"]["action"], "mongodb.auth_attempt")
        self.assertEqual(last_log["logdata"]["username"], "test_user")
        self.assertEqual(last_log["logdata"]["mechanism"], "SCRAM-SHA-256")
        self.assertIn("payload", last_log["logdata"]["auth_data"])

    def test_mongodb_command_attempt(self):
        """
        Try to run an unauthenticated MongoDB command.
        """
        with self.assertRaises(OperationFailure) as error:
            self.client.admin.command("listDatabases")

        self.assertEqual(error.exception.code, MONGODB_UNAUTHORIZED_CODE)

        last_log = get_mongodb_log(
            "mongodb.command", self.log_start, {"command": "listDatabases"}
        )
        self.assertIsNotNone(last_log)
        self.assertEqual(last_log["logtype"], 20001)
        self.assertEqual(last_log["dst_port"], MONGODB_PORT)
        self.assertEqual(last_log["logdata"]["action"], "mongodb.command")
        self.assertEqual(last_log["logdata"]["command"], "listDatabases")
        self.assertIn("listDatabases", last_log["logdata"]["query"])

    def tearDown(self):
        self.client.close()


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
