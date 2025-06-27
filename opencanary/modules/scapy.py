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
            default=[21, 22, 23, 80, 110, 443, 3306, 3389, 8080, 5900],
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
        print("== ScapyService (native Opencanary module) started ==")

        def detect_scan_flags(pkt):
            try:
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

                if flags == 0x00:
                    logtype, scan_type = LoggerBase.LOG_PORT_NMAPNULL, "NULL"
                elif flags == 0x01:
                    logtype, scan_type = LoggerBase.LOG_PORT_NMAPFIN, "FIN"
                elif flags == 0x02:
                    logtype, scan_type = LoggerBase.LOG_PORT_SYN, "SYN"
                elif flags == 0x29:
                    logtype, scan_type = LoggerBase.LOG_PORT_NMAPXMAS, "XMAS"
                else:
                    return

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
                self.logger.log(logdata)
            except Exception as ex:
                print(f"[ScapyService] Error in detect_scan_flags: {ex}")

        try:
            self.sniff(
                filter="tcp", prn=detect_scan_flags, store=0
            )
        except Exception as e:
            print(f"ScapyService sniffing failed: {e}")

    def configUpdated(self):
        pass
        
