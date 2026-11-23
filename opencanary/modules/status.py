from opencanary.modules import CanaryService
from datetime import datetime
from twisted.internet import reactor


class StatusLoop:
    def updateLoop(self):
        self.updateStatus()
        reactor.callLater(self.factory.delay, self.updateLoop)

    def updateStatus(self):
        data = {}
        data["logtype"] = self.factory.logger.LOG_STATUS_UPDATE
        data["logdata"] = {
            "LASTSTATUS": self.factory.lastUpdate,
            "ALERTS": self.factory.logger.tally,
            "DELAY": self.factory.delay,
        }

        self.factory.logger.log(data)

        self.factory.lastUpdate = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        self.factory.logger.tally = 0


class CanaryStatus(CanaryService):
    NAME = "status"

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.logger = logger
        # define the delay between status updates
        # units can be seconds (s), minutes (m), hours (h), days (d)
        self.interval = int(config.getVal("status.interval", default=1))
        self.intervalunit = config.getVal("status.intervalunit", default="d")
        # calc delay in seconds from units
        if self.intervalunit == "s":
            self.delay = self.interval
        elif self.intervalunit == "m":
            self.delay = self.interval * 60  # 60s
        elif self.intervalunit == "h":
            self.delay = self.interval * 3600  # 60s x 60m
        elif self.intervalunit == "d":
            self.delay = self.interval * 86400  # 60s x 60m x 24h
        else:
            self.delay = 86400  # default to 1 day
        self.lastUpdate = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    def startYourEngines(self):
        sl = StatusLoop()
        sl.factory = self
        reactor.callWhenRunning(sl.updateLoop)
