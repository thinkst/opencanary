"""Run real OpenCanary services in a disposable integration-test process."""

import importlib
import json
from pathlib import Path
import sys

from twisted.application.service import MultiService
from twisted.internet import reactor

from opencanary.config import Config
from opencanary.logger import getLogger

SERVICE_CLASSES = {
    "ftp": "CanaryFTP",
    "git": "CanaryGit",
    "http": "CanaryHTTP",
    "https": "CanaryHTTPS",
    "httpproxy": "HTTPProxy",
    "mongodb": "CanaryMongoDB",
    "mysql": "CanaryMySQL",
    "ntp": "CanaryNtp",
    "rdp": "CanaryRDP",
    "redis": "CanaryRedis",
    "sip": "CanarySIP",
    "ssh": "CanarySSH",
    "tcpbanner": "CanaryTCPBanner",
    "telnet": "Telnet",
    "tftp": "CanaryTftp",
    "vnc": "CanaryVNC",
}


def main():
    config_path, ready_path, *names = sys.argv[1:]
    config = Config(config_path)
    logger = getLogger(config)
    application = MultiService()
    listeners = {}
    for name in names:
        module = importlib.import_module(f"opencanary.modules.{name}")
        service = getattr(module, SERVICE_CLASSES[name])(config=config, logger=logger)
        services = service.getService()
        if not isinstance(services, list):
            services = [services]
        if len(services) != 1:
            raise ValueError(f"Expected one listener for {name}, got {len(services)}")
        listener = services[0]
        # Some modules omit device.listen_addr; never expose test listeners.
        listener.kwargs["interface"] = "127.0.0.1"
        listener.setServiceParent(application)
        listeners[name] = listener

    def start():
        try:
            application.startService()
            # Twisted's internet services retain their bound IListeningPort here.
            ports = {
                name: listener._port.getHost().port
                for name, listener in listeners.items()
            }
            ready = Path(ready_path)
            temporary = ready.with_suffix(".tmp")
            temporary.write_text(json.dumps(ports))
            temporary.replace(ready)
        except Exception:
            import traceback

            traceback.print_exc()
            reactor.stop()

    reactor.addSystemEventTrigger("before", "shutdown", application.stopService)
    reactor.callWhenRunning(start)
    reactor.run()


if __name__ == "__main__":
    main()
