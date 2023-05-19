import traceback
# import warnings
# warnings.filterwarnings("ignore", category=DeprecationWarning)
def warn(*args, **kwargs):
    pass
import warnings
warnings.warn = warn
from twisted.application import service
from twisted.application import internet
from twisted.internet.protocol import Factory
from pkg_resources import iter_entry_points

from opencanary.config import config
from opencanary.logger import getLogger
from opencanary.modules.http import CanaryHTTP
from opencanary.modules.https import CanaryHTTPS
from opencanary.modules.ftp import CanaryFTP
from opencanary.modules.ssh import CanarySSH
from opencanary.modules.telnet import Telnet
from opencanary.modules.httpproxy import HTTPProxy
from opencanary.modules.mysql import CanaryMySQL
from opencanary.modules.mssql import MSSQL
from opencanary.modules.ntp import CanaryNtp
from opencanary.modules.tftp import CanaryTftp
from opencanary.modules.vnc import CanaryVNC
from opencanary.modules.sip import CanarySIP
from opencanary.modules.git import CanaryGit
from opencanary.modules.redis import CanaryRedis
from opencanary.modules.tcpbanner import CanaryTCPBanner
from opencanary.modules.rdp import CanaryRDP

#from opencanary.modules.example0 import CanaryExample0
#from opencanary.modules.example1 import CanaryExample1

ENTRYPOINT = "canary.usermodule"
MODULES = [
    CanaryFTP,
    CanaryGit,
    CanaryHTTP,
    CanaryHTTPS,
    CanaryMySQL,
    CanaryNtp,
    CanaryRDP,
    CanaryRedis,
    CanarySIP,
    CanarySSH,
    CanaryTCPBanner,
    CanaryTftp,
    CanaryVNC,
    HTTPProxy,
    MSSQL,
    Telnet,
    # CanaryExample0,
    # CanaryExample1,
]

if config.moduleEnabled('snmp'):
    try:
        #Module need Scapy, but the rest of OpenCanary doesn't
        from opencanary.modules.snmp import CanarySNMP
        MODULES.append(CanarySNMP)
    except ImportError:
        print("Can't import SNMP. Please ensure you have Scapy installed.")
        pass

# NB: imports below depend on inotify, only available on linux
import sys
if sys.platform.startswith("linux"):
    from opencanary.modules.samba import CanarySamba
    from opencanary.modules.portscan import CanaryPortscan
    MODULES.append(CanarySamba)
    MODULES.append(CanaryPortscan)

logger = getLogger(config)

def start_mod(application, klass):
    try:
        obj = klass(config=config, logger=logger)
    except Exception as e:
        err = 'Failed to instantiate instance of class %s in %s. %s' % (
            klass.__name__,
            klass.__module__,
            traceback.format_exc()
        )
        logMsg({'logdata': err})
        return

    if hasattr(obj, 'startYourEngines'):
        try:
            obj.startYourEngines()
            msg = 'Ran startYourEngines on class %s in %s' % (
                klass.__name__,
                klass.__module__
                )
            logMsg({'logdata': msg})

        except Exception as e:
            err = 'Failed to run startYourEngines on %s in %s. %s' % (
                klass.__name__,
                klass.__module__,
                traceback.format_exc()
            )
            logMsg({'logdata': err})
    elif hasattr(obj, 'getService'):
        try:
            service = obj.getService()
            if not isinstance(service, list):
                service = [service]
            for s in service:
                s.setServiceParent(application)
            msg = 'Added service from class %s in %s to fake' % (
                klass.__name__,
                klass.__module__
                )
            logMsg({'logdata': msg})
        except Exception as e:
            err = 'Failed to add service from class %s in %s. %s' % (
                klass.__name__,
                klass.__module__,
                traceback.format_exc()
            )
            logMsg({'logdata': err})
    else:
        err = 'The class %s in %s does not have any required starting method.' % (
            klass.__name__,
            klass.__module__
        )
        logMsg({'logdata': err})

def logMsg(msg):
    data = {}
#    data['src_host'] = device_name
#    data['dst_host'] = node_id
    data['logdata'] = {'msg': msg}
    logger.log(data, retry=False)

application = service.Application("opencanaryd")

# List of modules to start
start_modules = []

# Add all custom modules
# (Permanently enabled as they don't officially use settings yet)
for ep in iter_entry_points(ENTRYPOINT):
    try:
        klass = ep.load(require=False)
        start_modules.append(klass)
    except Exception as e:
        err = 'Failed to load class from the entrypoint: %s. %s' % (
            str(ep),
            traceback.format_exc()
            )
        logMsg({'logdata': err})

# Add only enabled modules
start_modules.extend(filter(lambda m: config.moduleEnabled(m.NAME), MODULES))

for klass in start_modules:
    start_mod(application, klass)

msg = 'Canary running!!!'
logMsg({'logdata': msg})
