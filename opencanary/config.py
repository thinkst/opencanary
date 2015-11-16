import os, sys, json, copy, socket, itertools, string, subprocess
from os.path import expanduser
from pkg_resources import resource_filename

SAMPLE_SETTINGS = resource_filename(__name__, 'data/settings.json')
SETTINGS = 'opencanary.conf'

class Config:
    def __init__(self, configfile=SETTINGS):
        self.__config = None
        self.__configfile = configfile

        files = [configfile, "%s/.%s" % (expanduser("~"), configfile), "/etc/opencanaryd/%s"%configfile]

        for fname in files:
            try:
                with open(fname, "r") as f:
                    print "[-] Using config file: %s" % fname
                    self.__config = json.load(f)
                return
            except IOError as e:
                print "[-] Failed to open %s for reading (%s)" % (fname, e)
            except ValueError as e:
                print "[-] Failed to decode json from %s (%s)" % (fname, e)
                subprocess.call("cp -r %s /var/tmp/config-err-$(date +%%s)" % fname, shell=True)
            except Exception as e:
                print "[-] An error occured loading %s (%s)" % (fname, e)

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

    def setValues(self, params):
        """Set all the valid values in params and return a list of errors for invalid"""

        # silently ensure that node_id and mac are not modified via web
        sacred = ["device.node_id", "device.mac"]
        for k in sacred:
            if k in params:
                del params[k]

        # if dhcp is enabled, ignore the static ip settings
        if params.get("device.dhcp.enabled", False):
            static = ["device.ip_address", "device.netmask",
                      "device.gw", "device.dns1", "device.dns2"]
            for k in static:
                if k in params:
                    del params[k]

        # for each section, if disabled, delete ignore section's settings
        disabled_modules = tuple(filter(lambda m: not params.get("%s.enabled" % m, False), ["ftp", "ssh", "smb", "http"]))
        for k in params.keys():
            if not k.endswith("enabled") and k.startswith(disabled_modules):
                del params[k]
                continue

        # test options indpenedently for validity
        errors = []
        for key,value in params.iteritems():
            try:
                self.valid(key,value)
            except ConfigException as e:
                errors.append(e)

        # Test that no ports overlap
        ports = {k: v for k, v in self.__config.iteritems() if k.endswith(".port")}
        newports = {k: v for k, v in params.iteritems() if k.endswith(".port")}
        ports.update(newports)
        ports = [(port,setting) for setting, port in ports.iteritems()]
        ports.sort()

        for port, settings in itertools.groupby(ports, lambda x: x[0]):
            settings = list(settings)
            if len(settings) > 1:
                services = ", ".join([s[1].split(".")[0] for s in settings])
                errmsg = "More than one service uses this port (%s)" % services
                for (port, setting) in settings:
                    errors.append(ConfigException(setting, errmsg))

        # Delete invalid settings for which an error is reported
        for err in errors:
            if err.key in params:
                del params[err.key]

        # Update current settings
        self.__config.update(params)
        return errors

    def setVal(self, key, val):
        """Set value only if valid otherwise throw exception"""
        errs = self.setValues({key: val})

        # sucessful update
        if not errs:
            return

        # raise first error reported on the update key
        for e in errs:
            if e.key == key:
                raise e

    def valid(self, key, val):
        """
        Test an the validity of an invidual setting
        Raise config error message on failure.
        TODO: delegate module tests to appropriate module
        """

        if key.endswith(".enabled"):
            if not ((val is True) or (val is False)):
                raise ConfigException(key, "Boolean setting is not True or False (%s)" % val)

        if key.endswith(".port"):
            if (not isinstance(val,int)) or val < 1 or val > 65535:
                raise ConfigException(key, "Invalid port number (%s)" % val)

        # Max length of SSH version string is 255 chars including trailing CR and LF
        # https://tools.ietf.org/html/rfc4253
        if key == "ssh.version" and len(val) > 253:
            raise ConfigException(key, "SSH version string too long (%s..)" % val[:5])

        if key == "smb.filelist":
            extensions = ["PDF", "DOC", "DOCX"]
            for f in val:
                if "name" not in f:
                    raise ConfigException(key, "No filename specified for %s" % f)
                if "type" not in f:
                    raise ConfigException(key, "No filetype specified for %s" % f)
                if not f["name"]:
                    raise ConfigException(key, "Filename cannot be empty")
                if not f["type"]:
                    raise Configexception(key, "File type cannot be empty")
                if f["type"] not in extensions:
                    raise Configexception(key, "Extension %s is not supported" % f["type"])

        if key == "device.name":
            allowed_chars = string.ascii_letters + string.digits + "+-#_"

            if len(val) > 100:
                raise ConfigException(key, "Name cannot be longer than 100 characters")
            elif len(val) < 1:
                raise ConfigException(key, "Name ought to be at least one character")
            elif any(map(lambda x: x not in allowed_chars, val)):
                raise ConfigException(key, "Please use only characters, digits, any of the following: + - # _")

        if key == "device.desc":
            allowed_chars = string.ascii_letters + string.digits + "+-#_ "
            if len(val) > 100:
                raise ConfigException(key, "Name cannot be longer than 100 characters")
            elif len(val) < 1:
                raise ConfigException(key, "Name ought to be at least one character")
            elif any(map(lambda x: x not in allowed_chars, val)):
                raise ConfigException(key, "Please use only characters, digits, spaces and any of the following: + - # _")

        return True

    def saveSettings(self):
        """Backup config file to older version and save to new file"""
        try:
            cfg = self.__configfile
            if os.path.isfile(cfg):
                os.rename(cfg, cfg + ".bak")

            with open(cfg, "w") as f:
                json.dump(self.__config, f, sort_keys=True, indent=4, separators=(',', ': '))

        except Exception, e:
            print "[-] Failed to save config file %s" % e
            raise ConfigException("config", "%s" % e)


    def __repr__(self):
        return self.__config.__repr__()

    def __str__(self):
        return self.__config.__str__()

    def toDict(self):
        """ Return all settings as a dict """
        return self.__config

    def toJSON(self):
        """
        JSON representation of config
        """
        return json.dumps(self.__config, sort_keys=True, indent=4, separators=(',', ': '))


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
