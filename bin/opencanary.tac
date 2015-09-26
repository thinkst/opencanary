import warnings

from twisted.application import service
from twisted.application import internet
from twisted.internet.protocol import Factory


from opencanary.config import config
from opencanary.logger import getLogger
from opencanary.modules import CanaryServices

logger = getLogger(config)

def logMsg(msg):
    data = {}
#    data['src_host'] = device_name
#    data['dst_host'] = node_id
    data['logdata'] = {'msg': msg}
    logger.log(data, retry=False)

application = service.Application("opencanaryd")

for module in CanaryServices:
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
        if hasattr(loadmod, 'startYourEngines'):
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
