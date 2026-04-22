import os
import sys
import json
import itertools
import string
import re
from pathlib import Path

SETTINGS = "opencanary.conf"
USER_CONFIG_DIR = Path.home() / ".opencanary"
USER_CONFIG_PATH = USER_CONFIG_DIR / SETTINGS
LEGACY_USER_CONFIG_PATH = Path.home() / f".{SETTINGS}"
LEGACY_SYSTEM_CONFIG_DIR = Path("/etc/opencanary")
LEGACY_SYSTEM_CONFIG_PATH = LEGACY_SYSTEM_CONFIG_DIR / SETTINGS


def expand_vars(var):
    """Recursively replace environment variables in a dictionary, list or string with their respective values."""
    if isinstance(var, dict):
        for key, value in var.items():
            var[key] = expand_vars(value)
        return var
    if isinstance(var, (list, set, tuple)):
        return [expand_vars(v) for v in var]
    if isinstance(var, (str, bytes)):
        return os.path.expandvars(var)
    return var


def is_docker():
    cgroup = Path("/proc/self/cgroup")
    return (
        Path("/.dockerenv").is_file()
        or cgroup.is_file()
        and "docker" in cgroup.read_text()
    )


SERVICE_REGEXES = {
    "ssh.version": r"(SSH-(2.0|1.5|1.99|1.0)-([!-,\-./0-~]+(:?$|\s))(?:[ -~]*)){1,253}$",
}


class Config:
    def __init__(self, configfile=SETTINGS):
        self.__config = None
        self.__configfile = configfile

        files = [
            Path(configfile),
            USER_CONFIG_DIR / configfile,
            LEGACY_USER_CONFIG_PATH if configfile == SETTINGS else USER_CONFIG_DIR / configfile,
            LEGACY_SYSTEM_CONFIG_PATH if configfile == SETTINGS else LEGACY_SYSTEM_CONFIG_DIR / configfile,
        ]
        print(
            "** We hope you enjoy using OpenCanary. For more open source Canary goodness, head over to canarytokens.org. **"
        )
        for fname in files:
            try:
                with open(fname, "r") as f:
                    print("[-] Using config file: %s" % fname)
                    self.__config = json.load(f)
                    self.__config = expand_vars(self.__config)
                if Path(fname) == Path(configfile):
                    print(
                        "[-] Using the configuration file in the current directory."
                    )
                return
            except IOError as e:
                print("[-] Failed to open %s for reading (%s)" % (fname, e))
            except ValueError as e:
                print("[-] Failed to decode json from %s (%s)" % (fname, e))
            except Exception as e:
                print("[-] An error occurred loading %s (%s)" % (fname, e))
        if self.__config is None:
            print(
                f'No config file found. Please create one with "opencanary copyconfig" or place a config at "{USER_CONFIG_PATH}".'
            )
            sys.exit(1)

    def moduleEnabled(self, module_name):
        k = "%s.enabled" % module_name.lower()
        if k in self.__config:
            return bool(self.__config[k])
        return False

    def getVal(self, key, default=None):
        # throw exception to caller
        try:
            return self.__config[key]
        except KeyError as e:
            if default is not None:
                return default
            raise e

    def checkValues(self):  # noqa: C901
        """Set all the valid values in params and return a list of errors for invalid"""
        params = self.__config
        # test options indpenedently for validity
        errors = []
        for key, value in params.items():
            try:
                self.is_valid(key, value)
            except ConfigException as e:
                errors.append(e)

        # Test that no ports overlap
        ports = {k: int(v) for k, v in params.items() if k.endswith(".port")}
        ports = [(port, setting) for setting, port in ports.items()]
        ports.sort()

        for port, settings in itertools.groupby(ports, lambda x: x[0]):
            settings = list(settings)
            if len(settings) > 1:
                services = ", ".join([s[1].split(".")[0] for s in settings])
                errmsg = "More than one service uses this port (%s)" % services
                for port, setting in settings:
                    errors.append(ConfigException(setting, errmsg))

        return errors

    def is_valid(self, key, val):  # noqa: C901
        """
        Test an the validity of an individual setting
        Raise config error message on failure.
        TODO: delegate module tests to appropriate module
        """

        if key.endswith(".enabled"):
            if not ((val is True) or (val is False)):
                raise ConfigException(
                    key, "Boolean setting is not True or False (%s)" % val
                )

        if key.endswith(".port"):
            if not isinstance(val, int):
                raise ConfigException(
                    key, "Invalid port number (%s). Must be an integer." % val
                )
            if val < 1 or val > 65535:
                raise ConfigException(
                    key, "Invalid port number (%s). Must be between 1 and 65535." % val
                )
        # Max length of SSH version string is 255 chars including trailing CR and LF
        # https://tools.ietf.org/html/rfc4253
        if key == "ssh.version" and len(val) > 253:
            raise ConfigException(key, "SSH version string too long (%s..)" % val[:5])

        if key == "device.name":
            allowed_chars = string.ascii_letters + string.digits + "+-#_"

            if len(val) > 100:
                raise ConfigException(key, "Name cannot be longer than 100 characters")
            elif len(val) < 1:
                raise ConfigException(key, "Name ought to be at least one character")
            elif any(map(lambda x: x not in allowed_chars, val)):
                raise ConfigException(
                    key,
                    "Please use only characters, digits, any of the following: + - # _",
                )

        if key == "device.desc":
            allowed_chars = string.ascii_letters + string.digits + "+-#_ "
            if len(val) > 100:
                raise ConfigException(key, "Name cannot be longer than 100 characters")
            elif len(val) < 1:
                raise ConfigException(key, "Name ought to be at least one character")
            elif any(map(lambda x: x not in allowed_chars, val)):
                raise ConfigException(
                    key,
                    "Please use only characters, digits, spaces and any of the following: + - # _",
                )

        if key in SERVICE_REGEXES.keys():
            if not re.match(SERVICE_REGEXES[key], val):
                raise ConfigException(key, f"{val} is not valid.")

        return True

    def __repr__(self):
        return self.__config.__repr__()

    def __str__(self):
        return self.__config.__str__()

    def toDict(self):
        """Return all settings as a dict"""
        return self.__config

    def toJSON(self):
        """
        JSON representation of config
        """
        return json.dumps(
            self.__config, sort_keys=True, indent=4, separators=(",", ": ")
        )


class ConfigException(Exception):
    """Exception raised on invalid config value"""

    def __init__(self, key, msg):
        self.key = key
        self.msg = msg

    def __str__(self):
        return "%s: %s" % (self.key, self.msg)

    def __repr__(self):
        return "<%s %s (%s)>" % (self.__class__.__name__, self.key, self.msg)


config = Config()
errors = config.checkValues()
if errors:
    for error in errors:
        print(error)
    sys.exit(1)
