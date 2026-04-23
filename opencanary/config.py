import itertools
import json
import os
import re
import string
from json import JSONDecodeError
from pathlib import Path

SETTINGS = "opencanary.conf"
CONFIG_PATH_ENVVAR = "OPENCANARY_CONFIG_FILE"
USER_CONFIG_DIR = Path.home() / ".opencanary"
USER_CONFIG_PATH = USER_CONFIG_DIR / SETTINGS
LEGACY_USER_CONFIG_PATH = Path.home() / f".{SETTINGS}"
LEGACY_SYSTEM_CONFIG_DIR = Path("/etc/opencanary")
LEGACY_SYSTEM_CONFIG_PATH = LEGACY_SYSTEM_CONFIG_DIR / SETTINGS


def expand_vars(var):
    """Recursively replace environment variables in config values."""
    if isinstance(var, dict):
        return {key: expand_vars(value) for key, value in var.items()}
    if isinstance(var, list):
        return [expand_vars(value) for value in var]
    if isinstance(var, tuple):
        return tuple(expand_vars(value) for value in var)
    if isinstance(var, set):
        return {expand_vars(value) for value in var}
    if isinstance(var, str):
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
    def __init__(self, config, source_path=None):
        self.__config = dict(config)
        self.source_path = Path(source_path) if source_path is not None else None

    def moduleEnabled(self, module_name):
        key = f"{module_name.lower()}.enabled"
        if key in self.__config:
            return bool(self.__config[key])
        return False

    def getVal(self, key, default=None):
        try:
            return self.__config[key]
        except KeyError as exc:
            if default is not None:
                return default
            raise exc

    def checkValues(self):
        return validate_config(self)

    def is_valid(self, key, val):
        validate_config_value(key, val)
        return True

    def __repr__(self):
        return self.__config.__repr__()

    def __str__(self):
        return self.__config.__str__()

    def toDict(self):
        """Return all settings as a dict."""
        return dict(self.__config)

    def toJSON(self):
        """JSON representation of config."""
        return json.dumps(
            self.__config, sort_keys=True, indent=4, separators=(",", ": ")
        )


class ConfigException(Exception):
    """Exception raised on invalid config value."""

    def __init__(self, key, msg):
        self.key = key
        self.msg = msg

    def __str__(self):
        return "%s: %s" % (self.key, self.msg)

    def __repr__(self):
        return "<%s %s (%s)>" % (self.__class__.__name__, self.key, self.msg)


class ConfigLoadError(Exception):
    """Exception raised when no usable config file can be loaded."""

    def __init__(self, msg, attempts=None):
        super().__init__(msg)
        self.msg = msg
        self.attempts = attempts or []

    def __str__(self):
        return self.msg


def get_config_search_paths(configfile=SETTINGS):
    config_path = Path(configfile)
    candidates = [config_path]
    if configfile == SETTINGS:
        candidates.extend(
            [
                USER_CONFIG_PATH,
                LEGACY_USER_CONFIG_PATH,
                LEGACY_SYSTEM_CONFIG_PATH,
            ]
        )
    else:
        candidates.extend(
            [
                USER_CONFIG_DIR / config_path.name,
                LEGACY_SYSTEM_CONFIG_DIR / config_path.name,
            ]
        )

    unique_paths = []
    seen = set()
    for candidate in candidates:
        resolved = str(candidate)
        if resolved in seen:
            continue
        seen.add(resolved)
        unique_paths.append(candidate)
    return unique_paths


def load_config(configfile=SETTINGS, search_paths=None):
    attempts = []
    for path in search_paths or get_config_search_paths(configfile):
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = expand_vars(json.load(handle))
                return Config(data, source_path=path.resolve())
        except FileNotFoundError:
            attempts.append((path, "not found"))
        except JSONDecodeError as exc:
            attempts.append((path, f"invalid json ({exc})"))
        except OSError as exc:
            attempts.append((path, f"failed to open ({exc})"))

    messages = [f"{path}: {reason}" for path, reason in attempts if reason != "not found"]
    if messages:
        messages.append("No valid config file found.")
        raise ConfigLoadError("\n".join(messages), attempts=attempts)

    raise ConfigLoadError(
        f'No config file found. Please create one with "opencanary copyconfig" or place a config at "{USER_CONFIG_PATH}".',
        attempts=attempts,
    )


def validate_config(config):
    params = config.toDict() if isinstance(config, Config) else dict(config)
    errors = []
    for key, value in params.items():
        try:
            validate_config_value(key, value)
        except ConfigException as exc:
            errors.append(exc)

    ports = {key: int(value) for key, value in params.items() if key.endswith(".port")}
    by_port = sorted((port, setting) for setting, port in ports.items())
    for port, settings in itertools.groupby(by_port, lambda item: item[0]):
        settings = list(settings)
        if len(settings) <= 1:
            continue
        services = ", ".join(setting.split(".")[0] for _, setting in settings)
        errmsg = "More than one service uses this port (%s)" % services
        for _, setting in settings:
            errors.append(ConfigException(setting, errmsg))

    return errors


def validate_config_value(key, val):
    """
    Test the validity of an individual setting.
    Raise a config error on failure.
    """

    if key.endswith(".enabled") and val not in (True, False):
        raise ConfigException(key, "Boolean setting is not True or False (%s)" % val)

    if key.endswith(".port"):
        if not isinstance(val, int):
            raise ConfigException(
                key, "Invalid port number (%s). Must be an integer." % val
            )
        if val < 1 or val > 65535:
            raise ConfigException(
                key, "Invalid port number (%s). Must be between 1 and 65535." % val
            )

    if key == "ssh.version" and len(val) > 253:
        raise ConfigException(key, "SSH version string too long (%s..)" % val[:5])

    if key == "device.name":
        allowed_chars = string.ascii_letters + string.digits + "+-#_"
        if len(val) > 100:
            raise ConfigException(key, "Name cannot be longer than 100 characters")
        if len(val) < 1:
            raise ConfigException(key, "Name ought to be at least one character")
        if any(char not in allowed_chars for char in val):
            raise ConfigException(
                key,
                "Please use only characters, digits, any of the following: + - # _",
            )

    if key == "device.desc":
        allowed_chars = string.ascii_letters + string.digits + "+-#_ "
        if len(val) > 100:
            raise ConfigException(key, "Name cannot be longer than 100 characters")
        if len(val) < 1:
            raise ConfigException(key, "Name ought to be at least one character")
        if any(char not in allowed_chars for char in val):
            raise ConfigException(
                key,
                "Please use only characters, digits, spaces and any of the following: + - # _",
            )

    if key in SERVICE_REGEXES and not re.match(SERVICE_REGEXES[key], val):
        raise ConfigException(key, f"{val} is not valid.")

    return True
