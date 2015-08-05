import warnings

from twisted.application import service
from twisted.application import internet
from twisted.internet.protocol import Factory


from opencanary.config import config
from opencanary.logger import getLogger
from opencanary.modules.http import CanaryHTTP
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

#from opencanary.modules.example0 import CanaryExample0
#from opencanary.modules.example1 import CanaryExample1

MODULES = [Telnet, CanaryHTTP, CanaryFTP, CanarySSH, HTTPProxy, CanaryMySQL,
           MSSQL, CanaryVNC, CanaryTftp, CanaryNtp, CanarySIP]
           #CanaryExample0, CanaryExample1]
try:
    #Module needs RDP, but the rest of OpenCanary doesn't
    from opencanary.modules.rdp import CanaryRDP
    MODULES.append(CanaryRDP)
except ImportError:
    pass


try:
    #Module need Scapy, but the rest of OpenCanary doesn't
    from opencanary.modules.snmp import CanarySNMP
    MODULES.append(CanarySNMP)
except ImportError:
    pass

# NB: imports below depend on inotify, only available on linux
import sys
if sys.platform.startswith("linux"):
    from opencanary.modules.samba import CanarySamba
    from opencanary.modules.portscan import CanaryPortscan
    MODULES.append(CanarySamba)
    MODULES.append(CanaryPortscan)

logger = getLogger(config)

def logMsg(msg):
    data = {}
#    data['src_host'] = device_name
#    data['dst_host'] = node_id
    data['logdata'] = {'msg': msg}
    logger.log(data, retry=False)

application = service.Application("opencanaryd")

for module in MODULES:
    # skip if not enabled
    if not config.moduleEnabled(module.NAME):
        continue

    # newer type modules
    if issubclass(module, Factory):
        csf = sys.modules[module.__module__].CanaryServiceFactory(config, logger)
        internet.TCPServer(csf.port, csf).setServiceParent(application)
        continue

    # check if module is enabled
    try:
        loadmod = module(config=config, logger=logger)
        logMsg("Loaded module %s" % (module.NAME))
    except Exception as e:
        data = {'logdata': "Could not load module %s: %r" % (module.NAME, e)}
        logger.error(data)
        continue

    # start modules
    try:
        if module in [CanarySamba, CanaryPortscan]:
            loadmod.startYourEngines()
            logMsg("Start module %s" % (module.NAME))
            continue
    except:
        pass

    try:
        service = loadmod.getService()
        # check that canaryservice is defined
        # check that it has logtype defined
        factory = service.args[1]
        c = getattr(factory, "canaryservice", None)
        if c is not None:
            logtype = getattr(c, "logtype", None)
            if logtype is None:
                msg = "In future each module must define a single logtype."
                warnings.warn(msg, DeprecationWarning)

        service.setServiceParent(application)
        logMsg("Start module %s" % (module.NAME))
    except Exception as e:
        data = {'logdata': "Could not start module %s: %r" % (module.NAME, e)}
        logger.error(data)
        continue

logMsg("Canary running!!!")
