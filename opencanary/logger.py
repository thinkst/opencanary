import simplejson as json
import logging.config
import socket
import sys

from datetime import datetime
from logging.handlers import SocketHandler
from twisted.internet import reactor

class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

def getLogger(config):
    try:
        d = config.getVal('logger')
    except Exception as e:
        print >> sys.stderr, "Error: config does not have 'logger' section"
        exit(1)

    classname = d.get('class', None)
    if classname is None:
        print >> sys.stderr, "Logger section is missing the class key."
        exit(1)

    LoggerClass = globals().get(classname, None)
    if LoggerClass is None:
        print >> sys.stderr, "Logger class (%s) is not defined." % classname
        exit(1)

    kwargs = d.get('kwargs', None)
    if kwargs is None:
        print >> sys.stderr, "Logger section is missing the kwargs key."
        exit(1)

    try:
        logger = LoggerClass(config, **kwargs)
    except Exception as e:
        print >> sys.stderr, "An error occured initialising the logger class"
        print e
        exit(1)

    return logger

class LoggerBase(object):
    LOG_BASE_BOOT                               = 1000
    LOG_BASE_MSG                                = 1001
    LOG_BASE_DEBUG                              = 1002
    LOG_BASE_ERROR                              = 1003
    LOG_BASE_PING                               = 1004
    LOG_BASE_CONFIG_SAVE                        = 1005
    LOG_BASE_EXAMPLE                            = 1006
    LOG_FTP_LOGIN_ATTEMPT                       = 2000
    LOG_HTTP_GET                                = 3000
    LOG_HTTP_POST_LOGIN_ATTEMPT                 = 3001
    LOG_SSH_NEW_CONNECTION                      = 4000
    LOG_SSH_REMOTE_VERSION_SENT                 = 4001
    LOG_SSH_LOGIN_ATTEMPT                       = 4002
    LOG_SMB_FILE_OPEN                           = 5000
    LOG_PORT_SYN                                = 5001
    LOG_TELNET_LOGIN_ATTEMPT                    = 6001
    LOG_HTTPPROXY_LOGIN_ATTEMPT                 = 7001
    LOG_MYSQL_LOGIN_ATTEMPT                     = 8001
    LOG_MSSQL_LOGIN_SQLAUTH                     = 9001
    LOG_MSSQL_LOGIN_WINAUTH                     = 9002
    LOG_TFTP                                    = 10001
    LOG_NTP_MONLIST                             = 11001
    LOG_VNC                                     = 12001
    LOG_SNMP_CMD                                = 13001
    LOG_RDP                                     = 14001
    LOG_SIP_REQUEST                             = 15001
    LOG_USER_0                                  = 99000
    LOG_USER_1                                  = 99001
    LOG_USER_2                                  = 99002
    LOG_USER_3                                  = 99003
    LOG_USER_4                                  = 99004
    LOG_USER_5                                  = 99005
    LOG_USER_6                                  = 99006
    LOG_USER_7                                  = 99007
    LOG_USER_8                                  = 99008
    LOG_USER_9                                  = 99009

    def sanitizeLog(self, logdata):
        logdata['node_id'] = self.node_id
        logdata['local_time'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
        if not logdata.has_key('src_host'):
            logdata['src_host'] = ''
        if not logdata.has_key('src_port'):
            logdata['src_port'] = -1
        if not logdata.has_key('dst_host'):
            logdata['dst_host'] = ''
        if not logdata.has_key('dst_port'):
            logdata['dst_port'] = -1
        if not logdata.has_key('logtype'):
            logdata['logtype'] = self.LOG_BASE_MSG
        if not logdata.has_key('logdata'):
            logdata['logdata'] = {}
        return logdata

class PyLogger(LoggerBase):
    """
    Generic python logging
    """
    __metaclass__ = Singleton

    def __init__(self, config, handlers, formatters={}):
        self.node_id = config.getVal('device.node_id')

        # Build config dict to initialise
        # Ensure all handlers don't drop logs based on severity level
        for h in handlers:
            handlers[h]["level"] = "NOTSET"

        logconfig = {
            "version": 1,
            "formatters" : formatters,
            "handlers": handlers,
            # initialise all defined logger handlers
            "loggers": {
                self.node_id : {
                    "handlers": handlers.keys()
                }
            }
        }

        try:
            logging.config.dictConfig(logconfig)
        except Exception as e:
            print >> sys.stderr, "Invalid logging config"
            print type(e)
            print e
            exit(1)

        self.logger = logging.getLogger(self.node_id)

    def error(self, data):
        data['local_time'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
        msg = '[ERR] %r' % json.dumps(data, sort_keys=True)
        print >> sys.stderr, msg
        self.logger.warn(msg)

    def log(self, logdata, retry=True):
        logdata = self.sanitizeLog(logdata)
        self.logger.warn(json.dumps(logdata, sort_keys=True))


class SocketJSONHandler(SocketHandler):
    """Emits JSON messages over TCP delimited by newlines ('\n')"""

    def makeSocket(self, timeout=1):
        s = SocketHandler.makeSocket(self,timeout)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        return s

    def __init__(self, *args, **kwargs):
        SocketHandler.__init__(self, *args, **kwargs)
        self.retryStart = 0
        self.retryMax = 0
        self.retryFactor = 0

    def send(self, s, attempt=0):
        if attempt >= 10:
            print "Dropping log message due to too many failed sends"
            return

        if self.sock is None:
            self.createSocket()

        if self.sock:
            try:
                # TODO: Weirdly, one the other ends drops the
                # connection for the next msg, sendall still reports
                # successful write on a disconnected socket but then
                # on subsequent writes it fails correctly.
                self.sock.sendall(s)
                return
            except socket.error:
                self.sock.close()
                self.sock = None

        # Here, we've failed to send s so retry
        reactor.callLater(1.5, lambda x: self.send(s, attempt + 1), None)

    def makePickle(self, record):
        return record.getMessage() + "\n"


class HpfeedsHandler(logging.Handler):
    def __init__(self,host,port,ident, secret,channels):
        logging.Handler.__init__(self)
        self.host=str(host)
        self.port=int(port)
        self.ident=str(ident)
        self.secret=str(secret)
        self.channels=map(str,channels)
        hpc=hpfeeds.new(self.host, self.port, self.ident, self.secret)
        hpc.subscribe(channels)
        self.hpc=hpc

    def emit(self, record):
        try:
            msg = self.format(record)
            self.hpc.publish(self.channels,msg)
        except:
            print "Error on publishing to server"
