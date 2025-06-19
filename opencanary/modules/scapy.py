from opencanary.modules import CanaryService
import threading
from datetime import datetime

class ScapyService(CanaryService):
    NAME = "scapy"

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        try:
            from scapy.all import sniff, TCP, IP
            self.sniff = sniff
            self.TCP = TCP
            self.IP = IP
        except ImportError:
            print("scapy is not installed!")
            self.sniff = None

        self.ports = config.getVal("scapy.ports", default=[21, 22, 23, 80, 110, 139, 443, 445, 3306, 3389, 8080, 5900])
        self.enabled = config.getVal("scapy.enabled", default=False)
        self.should_run = False

    def startYourEngines(self, reactor=None):
        if not self.enabled or not self.sniff:
            print("ScapyService not enabled or scapy missing, not starting scan detector.")
            return
        self.should_run = True
        t = threading.Thread(target=self.sniff_scans, daemon=True)
        t.start()

    def sniff_scans(self):
        print("== ScapyService (native Opencanary module) started ==")

        def detect_scan_flags(pkt):
            TCP = self.TCP
            IP = self.IP
            if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                return
            tcp = pkt[TCP]
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst
            sport = tcp.sport
            dport = tcp.dport
            if dport not in self.ports:
                return
            flags = int(tcp.flags)
            scan_type = None
            logtype = None
            if flags == 0:
                logtype, scan_type = 5003, 'NULL'
            elif flags == 1:
                logtype, scan_type = 5005, 'FIN'
            elif flags == 41:
                logtype, scan_type = 5004, 'XMAS'
            elif flags == 2:
                logtype, scan_type = 5001, 'SYN'
            else:
                return

            data = {
                "src_host": src,
                "src_port": sport,
                "dst_host": dst,
                "dst_port": dport,
                "logtype": logtype,
                "scan_type": scan_type,
                "local_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"),
                "logdata": {"msg": f"Scan {scan_type} detected on port {dport} from {src}"}
            }
            # Send to Opencanary’s logger (not file!)
            self.logger.log(data)

        # Start the packet sniffer
        self.sniff(filter="tcp", prn=detect_scan_flags, store=0)

    def configUpdated(self):
        pass
