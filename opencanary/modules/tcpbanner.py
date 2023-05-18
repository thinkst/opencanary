from opencanary.modules import CanaryService
import socket

from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.application import internet

class ProtocolError(Exception):
    pass

class UnsupportedVersion(Exception):
    pass

class TCPBannerProtocol(Protocol):
    """
        Implementation of TCP Banner module - reply with a text banner
    """
    def __init__(self, factory, banner_id , accept_banner, send_banner,
                 alert_string_enabled ,alert_string, keep_alive_enabled, keep_alive_secret,
                 keep_alive_idle, keep_alive_interval, keep_alive_probes):
        self.factory = factory
        self.banner_id = banner_id
        self.accept_banner = accept_banner
        self.send_banner = send_banner
        self.alert_string_enabled = alert_string_enabled
        self.alert_string = alert_string
        self.keep_alive_enabled = keep_alive_enabled
        # once we send the secret key we disable alerting on keep-alive
        # connections
        self.keep_alive_disable_alerting = False
        self.keep_alive_secret = keep_alive_secret
        self.keep_alive_idle = keep_alive_idle
        self.keep_alive_interval = keep_alive_interval
        self.keep_alive_probes = keep_alive_probes

    def connectionMade(self):
        #We limit the data sent through to 255 chars
        try:
            data = str(self.accept_banner)[:255]

            logdata = {'FUNCTION': 'CONNECTION_MADE', 'DATA':data,
                    'BANNER_ID':str(self.banner_id)}

            if self.keep_alive_enabled:
                if hasattr(socket, 'TCP_KEEPIDLE'):
                    # overrides value (in seconds) of system-wide ipv4 tcp_keepalive_time
                    self.transport.getHandle().setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, self.keep_alive_idle)
                if hasattr(socket, 'TCP_KEEPINTVL'):
                    # overrides value (in seconds) of system-wide ipv4 tcp_keepalive_intvl
                    self.transport.getHandle().setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, int(self.keep_alive_interval))
                if hasattr(socket, 'TCP_KEEPCNT'):
                    # overrides value (in seconds) of system-wide ipv4 tcp_keepalive_probes
                    self.transport.getHandle().setsockopt(socket.SOL_TCP, socket.TCP_KEEPCNT, self.keep_alive_probes)
                # set keep alive on socket
                self.transport.setTcpKeepAlive(1)

                self.factory.canaryservice.logtype = self.factory.canaryservice.logger.LOG_TCP_BANNER_KEEP_ALIVE_CONNECTION_MADE
                self.factory.canaryservice.log(logdata, transport=self.transport)

            elif not self.alert_string_enabled:
                #flag says we need to wait for incoming data to include a string
                #so no point in logging anything here

                self.factory.canaryservice.logtype = self.factory.canaryservice.logger.LOG_TCP_BANNER_CONNECTION_MADE
                self.factory.canaryservice.log(logdata, transport=self.transport)

            self.transport.write(self.accept_banner)

        except OSError:
            print('Received an OSError. Likely the socket has closed.')
            self.factory.canaryservice.logtype = self.factory.canaryservice.logger.LOG_TCP_BANNER_CONNECTION_MADE
            self.factory.canaryservice.log(logdata, transport=self.transport)

    def dataReceived(self, data):
        """
        Received data from tcp connection after connection has been made.
        """
        try:
            if self.keep_alive_disable_alerting:
                self.transport.write(self.send_banner)
                return

            #We limit the data sent through to 255 chars
            data = data[:255]

            logdata = {'FUNCTION':'DATA_RECEIVED',
                       'BANNER_ID':str(self.banner_id)}
            try:
                logdata['DATA'] = data.rstrip().decode().encode('utf-8')
            except UnicodeDecodeError:
                logdata['DATA'] = data.rstrip().decode('unicode_escape').encode('utf-8')

            send_log = True

            if self.keep_alive_enabled:
                if self.keep_alive_secret != '' and self.keep_alive_secret in data:
                    self.keep_alive_disable_alerting = True
                    self.factory.canaryservice.logtype = self.factory.canaryservice.logger.LOG_TCP_BANNER_KEEP_ALIVE_SECRET_RECEIVED
                    logdata['SECRET_STRING'] = (self.keep_alive_secret).decode().encode('utf-8')
                else:
                    self.factory.canaryservice.logtype = self.factory.canaryservice.logger.LOG_TCP_BANNER_KEEP_ALIVE_DATA_RECEIVED
            else:
                self.factory.canaryservice.logtype = self.factory.canaryservice.logger.LOG_TCP_BANNER_DATA_RECEIVED
                if self.alert_string_enabled:
                    if self.alert_string in data:
                        logdata['ALERT_STRING'] = (self.alert_string).decode().encode('utf-8')
                    else:
                        send_log = False

            if send_log:
                self.factory.canaryservice.log(logdata, transport=self.transport)

            self.transport.write(self.send_banner)
        except (UnsupportedVersion, ProtocolError):
            self.transport.loseConnection()
            return

class TCPBannerFactory(Factory):
    def __init__(self, config=None, banner_id=1):
        self.banner_id = str(banner_id)
        self.accept_banner = config.getVal('tcpbanner_' + self.banner_id + '.initbanner','')\
            .encode('utf8').replace(b'\\n',b'\n').replace(b'\\r',b'\r')
        self.send_banner = config.getVal('tcpbanner_' + self.banner_id + '.datareceivedbanner','')\
            .encode('utf8').replace(b'\\n',b'\n').replace(b'\\r',b'\r')
        self.alert_string_enabled = config.getVal('tcpbanner_' + self.banner_id + '.alertstring.enabled', False)
        self.alert_string = config.getVal('tcpbanner_' + self.banner_id + '.alertstring','')\
            .encode('utf8').replace(b'\\n',b'\n').replace(b'\\r',b'\r')
        self.keep_alive_enabled = config.getVal('tcpbanner_' + self.banner_id + '.keep_alive.enabled', False)
        self.keep_alive_secret = config.getVal('tcpbanner_' + self.banner_id + '.keep_alive_secret', '')\
            .encode('utf8').replace(b'\\n',b'\n').replace(b'\\r',b'\r')
        # the defaults for the tcp keep alive values add up to 1 hour keep alive
        # 300 for the first probe + 300 * 11 for the interval probes = 3600
        self.keep_alive_idle = config.getVal('tcpbanner_' + self.banner_id + '.keep_alive_idle', 300)
        self.keep_alive_interval = config.getVal('tcpbanner_' + self.banner_id + '.keep_alive_interval', 300)
        self.keep_alive_probes = config.getVal('tcpbanner_' + self.banner_id + '.keep_alive_probes', 11)

    def buildProtocol(self, addr):
        return TCPBannerProtocol(self,self.banner_id ,self.accept_banner,
                                 self.send_banner,self.alert_string_enabled,
                                 self.alert_string, self.keep_alive_enabled,
                                 self.keep_alive_secret, self.keep_alive_idle,
                                 self.keep_alive_interval, self.keep_alive_probes)


class CanaryTCPBanner(CanaryService):
    NAME = 'tcpbanner'
    MAX_TCP_BANNERS = 10

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)

    def getService(self):
        services = []
        for i in range(1,self.config.getVal('tcpbanner.maxnum', default=self.MAX_TCP_BANNERS)+1):
            if self.config.getVal('tcpbanner_'+str(i)+'.enabled', False):
                factory = TCPBannerFactory(config=self.config, banner_id=i)
                factory.canaryservice = self
                port = self.config.getVal('tcpbanner_'+str(i)+'.port',default=8000+i)
                services.append(internet.TCPServer(port, factory))
        return services
