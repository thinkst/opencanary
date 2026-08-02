import sys

if sys.platform.startswith("linux"):
    from opencanary.modules import CanaryService, FileSystemWatcher
    import re

    class SambaLogWatcher(FileSystemWatcher):
        def __init__(self, logFile=None, logger=None):
            self.logger = logger
            FileSystemWatcher.__init__(self, fileName=logFile)

        def handleLines(self, lines=None):
            # Updated regex to match anywhere in the line (not just at start).
            # Samba 4.x may prepend a syslog timestamp before the smbd_audit token,
            # causing the original anchored regex (^.*smbd_audit) to fail.
            audit_re = re.compile(r"smbd_audit.*:\s*(.*$)")

            for line in lines:
                matches = audit_re.search(line)

                # Skip lines that do not match the correct RegEx pattern
                if matches is None:
                    continue

                raw_data = matches.groups()[0].split("|")

                # Samba 4.22+ with vfs_full_audit prefix "%U|%I|%S" produces
                # 6 fields: user|srcHost|shareName|action|status|path
                # Older Samba with extended prefix produces 13+ fields.
                # Pad to 13 elements so existing field indices remain valid.
                data = raw_data + [""] * max(0, 13 - len(raw_data))

                user = data[0] if data[0] else "anonymous"
                srcHost = data[1]

                if len(raw_data) <= 6:
                    # Short format (Samba 4.22+): user|srcHost|shareName|action|status|path
                    shareName   = data[2]
                    auditAction = data[3]
                    auditStatus = data[4]
                    path        = data[5] if len(raw_data) > 5 else ""
                    dstHost     = ""
                    srcHostName = ""
                    dstHostName = ""
                    smbVersion  = ""
                    smbArch     = ""
                    domainName  = ""
                else:
                    # Long format (older Samba)
                    dstHost     = data[2]
                    srcHostName = data[3]
                    shareName   = data[4]
                    dstHostName = data[5]
                    smbVersion  = data[6]
                    smbArch     = data[7]
                    domainName  = data[9]
                    auditAction = data[10]
                    auditStatus = data[11]
                    path        = data[12]

                log_entry = {}
                log_entry["src_host"] = srcHost
                log_entry["src_port"] = "-1"
                log_entry["dst_host"] = dstHost
                log_entry["dst_port"] = 445
                log_entry["logtype"] = self.logger.LOG_SMB_FILE_OPEN
                log_entry["logdata"] = {
                    "USER": user,
                    "REMOTENAME": srcHostName,
                    "SHARENAME": shareName,
                    "LOCALNAME": dstHostName,
                    "SMBVER": smbVersion,
                    "SMBARCH": smbArch,
                    "DOMAIN": domainName,
                    "AUDITACTION": auditAction,
                    "STATUS": auditStatus,
                    "FILENAME": path,
                }
                self.logger.log(log_entry)

    class CanarySamba(CanaryService):
        NAME = "smb"

        def __init__(self, config=None, logger=None):
            CanaryService.__init__(self, config=config, logger=logger)
            self.audit_file = config.getVal(
                "smb.auditfile", default="/var/log/samba-audit.log"
            )
            self.config = config

        def startYourEngines(self, reactor=None):
            # create samba run dir, so testparm doesn't error
            # try:
            #    os.stat('/var/run/samba')
            # except OSError:
            #    os.mkdir('/var/run/samba')

            fs = SambaLogWatcher(logFile=self.audit_file, logger=self.logger)
            fs.start()

    # Alias for backward compatibility and explicit import in opencanary.tac
    CanarySMB = CanarySamba
