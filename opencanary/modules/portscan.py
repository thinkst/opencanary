from opencanary.modules import CanaryService
from opencanary.modules import FileSystemWatcher
import os
import re
import shutil

class SynLogWatcher(FileSystemWatcher):
    def __init__(self, logger=None, logFile=None, ignore_localhost=False, ignore_ports=None):
        if ignore_ports is None:
            ignore_ports = []
        self.logger = logger
        self.ignore_localhost = ignore_localhost
        self.ignore_ports = ignore_ports
        #print ('SynLogWatcher started')
        FileSystemWatcher.__init__(self, fileName=logFile)

    def handleLines(self, lines=None):
        for line in lines:
            try:
                if 'canaryfw: ' in line:
                    logtype = self.logger.LOG_PORT_SYN
                    (rubbish, log) = line.split('canaryfw: ')
                elif "canarynmapNULL" in line:
                    logtype = self.logger.LOG_PORT_NMAPNULL
                    (rubbish, log) = line.split('canarynmapNULL: ')
                elif "canarynmapXMAS" in line:
                    logtype = self.logger.LOG_PORT_NMAPXMAS
                    (rubbish, log) = line.split('canarynmapXMAS: ')
                elif "canarynmapFIN" in line:
                    logtype = self.logger.LOG_PORT_NMAPFIN
                    (rubbish, log) = line.split('canarynmapFIN: ')
                elif 'canarynmap: ' in line:
                    logtype = self.logger.LOG_PORT_NMAPOS
                    (rubbish, log) = line.split('canarynmap: ')
                else:
                    continue
            except ValueError:
                continue
            tags = log.split(' ')
            kv = {}
            for tag in tags:
                if tag.find('=') >= 0:
                    (key, val) = tag.split('=')
                else:
                    key = tag
                    val = ''
                kv[key]=val

            try:
                #we've seen empty tags creep in. weed them out.
                kv.pop('')
            except:
                pass

            data = {}
            data['src_host'] = kv.pop('SRC')
            data['src_port'] = kv.pop('SPT')
            data['dst_host'] = kv.pop('DST')
            data['dst_port'] = kv.pop('DPT')
            data['logtype']  = logtype
            data['logdata']  = kv
            if self.ignore_localhost and data.get('src_host', False) == '127.0.0.1':
                continue
            if int(data.get('dst_port', -1)) in self.ignore_ports:
                continue

            
            self.logger.log(data)

class CanaryPortscan(CanaryService):
    NAME = 'portscan'

    def __init__(self,config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.audit_file = config.getVal('portscan.logfile', default='/var/log/kern.log')
        self.synrate = int(config.getVal('portscan.synrate', default=5))
        self.nmaposrate = config.getVal('portscan.nmaposrate', default='5')
        self.lorate = config.getVal('portscan.lorate', default='3')
        self.listen_addr = config.getVal('device.listen_addr', default='')
        self.ignore_localhost = config.getVal('portscan.ignore_localhost', default=False)
        self.ignore_ports = config.getVal('portscan.ignore_ports', default=[])
        self.config = config

        try:
            self.synrate = int(self.synrate)
        except:
            self.synrate = 5

        try:
            self.nmaposrate = int(self.nmaposrate)
        except:
            self.nmaposrate = 5

        try:
            self.lorate = int(self.lorate)
        except:
            self.lorate = 3

    def getIptablesPath(self):
        return shutil.which('iptables') or '/sbin/iptables'

    def startYourEngines(self, reactor=None):
        # Logging rules for loopback interface.
        # This is separate from the canaryfw rule as the canary watchdog was
        # causing console-side noise in the logs.
        iptables_path=self.getIptablesPath()
        os.system('sudo {0} -t mangle -D PREROUTING -p tcp -i lo -j LOG --log-level=warning --log-prefix="canaryfw: " -m limit --limit="{1}/hour"'.format(iptables_path, self.lorate))
        os.system('sudo {0} -t mangle -A PREROUTING -p tcp -i lo -j LOG --log-level=warning --log-prefix="canaryfw: " -m limit --limit="{1}/hour"'.format(iptables_path, self.lorate))

        # Logging rules for canaryfw.
        # We ignore loopback interface traffic as it is taken care of in above rule
        os.system('sudo {0} -t mangle -D PREROUTING -p tcp --syn -j LOG --log-level=warning --log-prefix="canaryfw: " -m limit --limit="{1}/second" ! -i lo'.format(iptables_path, self.synrate))
        os.system('sudo {0} -t mangle -A PREROUTING -p tcp --syn -j LOG --log-level=warning --log-prefix="canaryfw: " -m limit --limit="{1}/second" ! -i lo'.format(iptables_path, self.synrate))

        # os.system('sudo /sbin/iptables -t mangle -D PREROUTING -p tcp {dst} --syn -j LOG --log-level=warning --log-prefix="canaryfw: " -m limit --limit="{synrate}/second"'
        #             .format(dst=(('--destination '+self.listen_addr) if len(self.listen_addr) else ''),
        #                 synrate=self.synrate))
        # os.system('sudo /sbin/iptables -t mangle -A PREROUTING -p tcp {dst} --syn -j LOG --log-level=warning --log-prefix="canaryfw: " -m limit --limit="{synrate}/second"'
        #             .format(dst=(('--destination '+self.listen_addr) if len(self.listen_addr) else ''),
        #                 synrate=self.synrate))

         # Match the T3 probe of the nmap OS detection based on TCP flags and TCP options string
        os.system('sudo {0} -t mangle -D PREROUTING -p tcp --tcp-flags ALL URG,PSH,SYN,FIN -m u32 --u32 "40=0x03030A01 && 44=0x02040109 && 48=0x080Affff && 52=0xffff0000 && 56=0x00000402" -j LOG --log-level=warning --log-prefix="canarynmap: " -m limit --limit="{1}/second"'.format(iptables_path, self.nmaposrate))
        os.system('sudo {0} -t mangle -A PREROUTING -p tcp --tcp-flags ALL URG,PSH,SYN,FIN -m u32 --u32 "40=0x03030A01 && 44=0x02040109 && 48=0x080Affff && 52=0xffff0000 && 56=0x00000402" -j LOG --log-level=warning --log-prefix="canarynmap: " -m limit --limit="{1}/second"'.format(iptables_path, self.nmaposrate))

        # Nmap Null Scan
        os.system('sudo {0} -t mangle -D PREROUTING -p tcp -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12=0x50000400" -j LOG --log-level=warning --log-prefix="canarynmapNULL: " -m limit --limit="{1}/second"'.format(iptables_path, self.nmaposrate))
        os.system('sudo {0} -t mangle -A PREROUTING -p tcp -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12=0x50000400" -j LOG --log-level=warning --log-prefix="canarynmapNULL: " -m limit --limit="{1}/second"'.format(iptables_path, self.nmaposrate))

        # Nmap Xmas Scan
        os.system('sudo {0} -t mangle -D PREROUTING -p tcp -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12=0x50290400" -j LOG --log-level=warning --log-prefix="canarynmapXMAS: " -m limit --limit="{1}/second"'.format(iptables_path, self.nmaposrate))
        os.system('sudo {0} -t mangle -A PREROUTING -p tcp -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12=0x50290400" -j LOG --log-level=warning --log-prefix="canarynmapXMAS: " -m limit --limit="{1}/second"'.format(iptables_path, self.nmaposrate))

        # Nmap Fin Scan
        os.system('sudo {0} -t mangle -D PREROUTING -p tcp -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12=0x50010400" -j LOG --log-level=warning --log-prefix="canarynmapFIN: " -m limit --limit="{1}/second"'.format(iptables_path, self.nmaposrate))
        os.system('sudo {0} -t mangle -A PREROUTING -p tcp -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12=0x50010400" -j LOG --log-level=warning --log-prefix="canarynmapFIN: " -m limit --limit="{1}/second"'.format(iptables_path, self.nmaposrate))

        fs = SynLogWatcher(logFile=self.audit_file, logger=self.logger, ignore_localhost=self.ignore_localhost, ignore_ports=self.ignore_ports)
        fs.start()

    def configUpdated(self,):
        pass
