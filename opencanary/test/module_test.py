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

import json
import unittest

# These libraries are only needed by the test suite and so aren't in the
# OpenCanary requirements, there is a requirements.txt file in the tests folder
# Simply run `pip install -r opencanary/test/requirements.txt`
import requests


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


if __name__ == "__main__":
    unittest.main()
