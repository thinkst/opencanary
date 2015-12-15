import sys
import warnings
import os.path
from pkg_resources import resource_filename
from twisted.application import internet
from twisted.internet.protocol import Factory
from twisted.internet.protocol import DatagramProtocol

from opencanary.honeycred import *

# Monkey-patch-replace Twisted Protocol with CanaryProtocol class
from twisted.internet import protocol

class CanaryProtocol(protocol.Protocol):
    """TCP protocols (ie. descedents of this class) gain a log method that be
    can be called with just the event data, as transport data is added here"""

    def log(self, *args, **kwargs):
        if hasattr(self, 'factory') and hasattr(self.factory, 'log'):
            kwargs['transport'] = self.transport
            return self.factory.log(*args, **kwargs)

        raise AttributeError("""Instance of %s does not have 'factory' attribute
        or factory does not have a log function.""" % self.__class__.__name__ )

protocol.Protocol = CanaryProtocol

class CanaryService(object):
    NAME = 'baseservice'

    def __init__(self,config=None, logger=None):
        self.config = config
        self.logger = logger
        self.logtype = None

        # if config contains honeycreds, create basic honeycreds class
        self.creds = config.getVal("%s.honeycreds" % self.NAME, [])
        if self.creds:
            self.honeyCredHook = buildHoneyCredHook(self.creds)

    @classmethod
    def resource_dir(klass):
        """Read-Only module resource directory"""
        path = os.path.join("data", klass.NAME)
        return resource_filename(__name__, path)

    @classmethod
    def resource_filename(klass, *args):
        """Access read-only data (installed with package)"""
        return os.path.join(klass.resource_dir(), *args)

    def log(self, logdata, **kwargs):
        """
        Log a module event

        For brevity, protocols may pass in Twisted transport argument
        for logger to get the IPs and ports of the connection.
        """
        data = {
            'logtype' : self.logtype,
            'logdata' : logdata
        }

        logtype = kwargs.pop('logtype', None)
        if logtype:
            msg = """Passing in the logtype to log is deprecated. (In future each module will have only only logtype.)"""
            warnings.warn(msg, DeprecationWarning)
            data['logtype'] = logtype

        transport = kwargs.pop('transport', None)
        if transport:
            us = transport.getHost()
            peer = transport.getPeer()
            data['src_host'] = peer.host
            data['src_port'] = peer.port
            data['dst_host'] = us.host
            data['dst_port'] = us.port

        # otherwise the module can include IPs and ports as kwargs
        data.update(kwargs)

        # run pre-log hooks
        if getattr(self ,"honeyCredHook", None):
            username = logdata.get("USERNAME", None)
            password = logdata.get("PASSWORD", None)
            if username or password:
                data["honeycred"] = self.honeyCredHook(username, password)

        self.logger.log(data)

    def getService(self):
        """Return service to be run

        This handles the easy case where the CanaryService class is
        also the Factory/Datagram class. Subclasses should override
        this if more intricracy is needed.
        """
        if isinstance(self, Factory):
            return internet.TCPServer(self.port, self)
        elif isinstance(self, DatagramProtocol):
            return internet.UDPServer(self.port, self)

        err = 'The class %s does not inherit from either Factory or DatagramProtocol.' % (
            self.__class__.__name__
            )
        raise Exception(err)


if sys.platform.startswith("linux"):
    from twisted.python import filepath
    from twisted.internet import inotify
    from twisted.python._inotify import INotifyError
    from twisted.internet.inotify import IN_CREATE
    import datetime
    import os

    class FileSystemWatcher(object):

        def __init__(self, fileName=None):
            self.path = fileName
            self.log_dir = os.path.dirname(os.path.realpath(self.path))
            self.f = None

        def reopenFiles(self, skipToEnd=True):
            if self.f:
                self.f.close()

            try:
                self.f = open(self.path)
                if skipToEnd:
                    self.f.seek(0, 2)
            except IOError as e:
                self.f = None

            self.notifier.startReading()
            try:
                self.notifier.ignore(filepath.FilePath(self.path))
            except KeyError:
                pass

            try:
                self.notifier.watch(filepath.FilePath(self.path),
                                    callbacks=[self.onChange])
            except INotifyError:
                self.notifier.watch(filepath.FilePath(self.log_dir), mask=IN_CREATE,
                                    callbacks=[self.onDirChange])

        def start(self):
            self.notifier = inotify.INotify()
            self.reopenFiles()

        def handleLines(self, lines=None):
            pass

        def processAuditLines(self,):
            if not self.f:
                return

            lines = self.f.read().strip().split('\n')

            self.handleLines(lines=lines)


        def onChange(self, watch, path, mask):
            #print path, 'changed', mask # or do something else!
            if mask != 2:
                self.reopenFiles()

            self.processAuditLines()


        def onDirChange(self, watch, path, mask):
            #print path, ' dir changed', mask # or do something else!
            #import pdb; pdb.set_trace()
            try:
                self.notifier.ignore(filepath.FilePath(self.log_dir))
            except KeyError:
                pass

            if mask != 2:
                self.reopenFiles(skipToEnd=False)

            self.processAuditLines()
