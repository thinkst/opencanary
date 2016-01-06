import sys

if sys.platform.startswith("linux"):
    from opencanary.modules import CanaryService, FileSystemWatcher
    from opencanary.config import ConfigException

    import os, re, random, shutil, time
    from datetime import datetime

    class SambaLogWatcher(FileSystemWatcher):

        def __init__(self, logFile=None, logger=None):
            self.logger = logger
            FileSystemWatcher.__init__(self, fileName=logFile)

        def handleLines(self, lines=None):
            #samba4 re
            audit_re = re.compile(r'.*smbd_audit: ([^|]+?)[|]([^|]+?)[|]([^|]+?)[|]([^|]+?)[|]([^|]+?)[|]([^|]+?)[|]([^|]+?)[|]([^|]+?)[|]([^|]+?)[|]([^|]+?)[|]([^|]+?)[|]([^|]+?)[|](.*)')

            #samba 3 re
            #audit_re = re.compile(r'.*smbd\[[0-9]+\]: (.*)')
            for line in lines:
                    matches = audit_re.match(line)
                    (user,remoteIP,localIP,remoteName,shareName,
                    localName,smbVer,smbArch,timeStamp,domainName,
                    auditAction,auditStatus,fileName) = matches.groups()

                    data = {}
                    data['src_host'] = remoteIP
                    data['src_port'] = '-1'
                    data['dst_host'] = localIP
                    data['dst_port'] = 445
                    data['logtype'] =  self.logger.LOG_SMB_FILE_OPEN
                    data['logdata'] = {'USER':user, 'REMOTENAME': remoteName, 'SHARENAME': shareName,
                                       'LOCALNAME': localName, 'SMBVER': smbVer, 'SMBARCH': smbArch,
                                       'DOMAIN': domainName, 'AUDITACTION': auditAction,
                                       'STATUS':auditStatus, 'FILENAME': fileName}
                    self.logger.log(data)

    class CanarySamba(CanaryService):
        NAME = 'smb'
        def __init__(self,config=None, logger=None):
            CanaryService.__init__(self, config=config, logger=logger)
            self.audit_file = config.getVal('smb.auditfile', default='/var/log/samba-audit.log')
            self.sharepath = config.getVal('smb.sharepath', default='/briar/smb/openshare')
            self.config = config

        def startYourEngines(self, reactor=None):
            #create samba run dir, so testparm doesn't error
            #try:
            #    os.stat('/var/run/samba')
            #except OSError:
            #    os.mkdir('/var/run/samba')

            fs = SambaLogWatcher(logFile=self.audit_file, logger=self.logger)
            fs.start()


