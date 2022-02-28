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
            audit_re = re.compile(r'^.*smbd_audit:.*$')

            for line in lines:
                    matches = audit_re.match(line)

                    #Skip lines that do not match the correct RegEx pattern
                    if matches is None:
                           continue

                    data = line.split('smbd_audit:',1)[-1].strip().split('|')

                    user = data[0]
                    srcHost = data[1]
                    dstHost = data[2]
                    srcHostName = data[3]
                    shareName = data[4]
                    dstHostName = data[5]
                    smbVersion = data[6]
                    smbArch = data[7]
                    domainName = data[9]
                    auditAction = data[10]
                    auditStatus = data[11]
                    path = data[12]

                    if user == "":
                      user = "anonymous"

                    data = {}
                    data['src_host'] = srcHost
                    data['src_port'] = '-1'
                    data['dst_host'] = dstHost
                    data['dst_port'] = 445
                    data['logtype'] =  self.logger.LOG_SMB_FILE_OPEN
                    data['logdata'] = {'USER':user, 'REMOTENAME': srcHostName, 'SHARENAME': shareName,
                                       'LOCALNAME': dstHostName, 'SMBVER': smbVersion, 'SMBARCH': smbArch,
                                       'DOMAIN': domainName, 'AUDITACTION': auditAction,
                                       'STATUS':auditStatus, 'FILENAME': path}
                    self.logger.log(data)

    class CanarySamba(CanaryService):
        NAME = 'smb'
        def __init__(self,config=None, logger=None):
            CanaryService.__init__(self, config=config, logger=logger)
            self.audit_file = config.getVal('smb.auditfile', default='/var/log/samba-audit.log')
            self.config = config

        def startYourEngines(self, reactor=None):
            #create samba run dir, so testparm doesn't error
            #try:
            #    os.stat('/var/run/samba')
            #except OSError:
            #    os.mkdir('/var/run/samba')

            fs = SambaLogWatcher(logFile=self.audit_file, logger=self.logger)
            fs.start()
