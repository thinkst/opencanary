from opencanary.modules import CanaryService
from datetime import datetime
import threading

from opencanary.logger import LoggerBase

class ScapyService(CanaryService):
    NAME = "scapy"

    def __init__(self, config=None, logger=None):
        super().__init__(config=config, logger=logger)
        try:
            from scapy.all import sniff, TCP, IP
        except ImportError:
            print("[!] Python scapy is not installed. Disabling ScapyService.")
            self.sniff = None
            return
        self.sniff = sniff
        self.TCP = TCP
        self.IP = IP
        self.ports = self._get_ports(config)
        self.enabled = bool(config.getVal("scapy.enabled", default=False))
        self.should_run = False

    def _get_ports(self, config):
        return config.getVal(
            "scapy.ports",
            default=[21, 22, 23, 80, 110, 139, 443, 445, 3306, 3389, 8080, 5900],
        )

    def startYourEngines(self, reactor=None):
        if not self.enabled or not self.sniff:
            print("ScapyService: Not enabled or scapy missing, not starting scan detector.")
            return
        if self.should_run:
            print("ScapyService: Already running.")
            return
        self.should_run = True
        t = threading.Thread(target=self.sniff_scans, daemon=True)
        t.start()
        print("ScapyService scan detection started.")

    def sniff_scans(self):
        """
        This thread will sniff packets on the interface for TCP scan traffic on the given ports.
        Detected scans are logged using the logger API as per standard Opencanary modules.
        """
        print("== ScapyService (native Opencanary module) started ==")

        def detect_scan_flags(pkt):
            # Require TCP and IP layers only
            if not pkt.haslayer(self.TCP) or not pkt.haslayer(self.IP):
                return
            tcp = pkt[self.TCP]
            ip = pkt[self.IP]
            src = ip.src
            dst = ip.dst
            sport = tcp.sport
            dport = tcp.dport
            if dport not in self.ports:
                return

            flags = int(tcp.flags)
            # Map nmap/scan TCP flag values to scan-type and logger constant
            scan_logtypes = {
                0:   (LoggerBase.LOG_PORT_NMAPNULL, "NULL"),     # No flags set
                1:   (LoggerBase.LOG_PORT_NMAPFIN, "FIN"),       # FIN only set
                2:   (LoggerBase.LOG_PORT_SYN, "SYN"),           # SYN only set
                41:  (LoggerBase.LOG_PORT_NMAPXMAS, "XMAS"),     # FIN+PSH+URG: "Xmas"
            }
            entry = scan_logtypes.get(flags)
            if not entry:
                return
            logtype, scan_type = entry

            logdata = {
                "src_host": src,
                "src_port": sport,
                "dst_host": dst,
                "dst_port": dport,
                "logtype": logtype,
                "scan_type": scan_type,
                "local_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"),
                "logdata": {
                    "msg": f"TCP scan type={scan_type} detected on port {dport} from {src}",
                },
            }
            # Submit to opencanary logger pipeline
            self.logger.log(logdata)

        # Scapy "sniff" is blocking, so run in background thread
        try:
            self.sniff(
                filter="tcp", prn=detect_scan_flags, store=0
            )
        except Exception as e:
            print(f"ScapyService sniffing failed: {e}")

    def configUpdated(self):
        pass
