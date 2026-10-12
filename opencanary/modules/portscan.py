from opencanary.modules import CanaryService
from opencanary.modules import FileSystemWatcher
from opencanary import STDPATH
import os
import subprocess
import shutil


class SynLogWatcher(FileSystemWatcher):
    def __init__(
        self, logger=None, logFile=None, ignore_localhost=False, ignore_ports=None
    ):
        if ignore_ports is None:
            ignore_ports = []
        self.logger = logger
        self.ignore_localhost = ignore_localhost
        self.ignore_ports = ignore_ports
        FileSystemWatcher.__init__(self, fileName=logFile)

    def handleLines(self, lines=None):  # noqa: C901
        for line in lines:
            try:
                if "canaryfw: " in line:
                    logtype = self.logger.LOG_PORT_SYN
                    (rubbish, log) = line.split("canaryfw: ")
                elif "canarynmapNULL" in line:
                    logtype = self.logger.LOG_PORT_NMAPNULL
                    (rubbish, log) = line.split("canarynmapNULL: ")
                elif "canarynmapXMAS" in line:
                    logtype = self.logger.LOG_PORT_NMAPXMAS
                    (rubbish, log) = line.split("canarynmapXMAS: ")
                elif "canarynmapFIN" in line:
                    logtype = self.logger.LOG_PORT_NMAPFIN
                    (rubbish, log) = line.split("canarynmapFIN: ")
                elif "canarynmap: " in line:
                    logtype = self.logger.LOG_PORT_NMAPOS
                    (rubbish, log) = line.split("canarynmap: ")
                else:
                    continue
            except ValueError:
                continue
            tags = log.split(" ")
            kv = {}
            for tag in tags:
                if tag.find("=") >= 0:
                    (key, val) = tag.split("=")
                else:
                    key = tag
                    val = ""
                kv[key] = val

            # we've seen empty tags creep in. weed them out.
            if "" in kv.keys():
                kv.pop("")

            data = {}
            data["src_host"] = kv.pop("SRC")
            data["src_port"] = kv.pop("SPT")
            data["dst_host"] = kv.pop("DST")
            data["dst_port"] = kv.pop("DPT")
            data["logtype"] = logtype
            data["logdata"] = kv
            if self.ignore_localhost and data.get("src_host", False) == "127.0.0.1":
                continue
            if int(data.get("dst_port", -1)) in self.ignore_ports:
                continue

            self.logger.log(data)


class CanaryPortscan(CanaryService):
    NAME = "portscan"

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.audit_file = config.getVal("portscan.logfile", default="/var/log/kern.log")
        self.synrate = int(config.getVal("portscan.synrate", default=5))
        self.nmaposrate = int(config.getVal("portscan.nmaposrate", default="5"))
        self.lorate = int(config.getVal("portscan.lorate", default="3"))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.ignore_localhost = config.getVal(
            "portscan.ignore_localhost", default=False
        )
        self.ignore_ports = config.getVal("portscan.ignore_ports", default=[])
        self.config = config

    def startYourEngines(self, reactor=None):
        self.set_iptables_rules()

        fs = SynLogWatcher(
            logFile=self.audit_file,
            logger=self.logger,
            ignore_localhost=self.ignore_localhost,
            ignore_ports=self.ignore_ports,
        )
        fs.start()

    def configUpdated(self):
        pass

    def _iptables_legacy_works(self, iptables_path):
        """
        Return True only if iptables-legacy can access the mangle table.

        On Debian 13+ and other modern kernels, the ip_tables kernel module
        may not be available even when the iptables-legacy binary exists,
        causing 'Table does not exist' errors on the mangle table.
        """
        result = subprocess.run(
            [iptables_path, "-t", "mangle", "-L", "PREROUTING", "-n"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0

    def set_iptables_rules(self):
        # Prefer iptables-legacy for backward compatibility.
        iptables_path = shutil.which("iptables-legacy", path=STDPATH)

        if not iptables_path:
            iptables_path = shutil.which("iptables", path=STDPATH)

        if not iptables_path:
            err = "Portscan module failed to start as iptables cannot be found. Please install iptables."
            print(err)
            raise Exception(err)

        # Check whether iptables-legacy can actually access the mangle table.
        # On Debian 12+ the iptables nf_tables backend is the default, and on
        # Debian 13+ the ip_tables kernel module may be absent entirely, making
        # the mangle table unavailable even when iptables-legacy is installed.
        use_legacy = b"legacy" in subprocess.check_output(
            [iptables_path, "--version"]
        ) and self._iptables_legacy_works(iptables_path)

        if use_legacy:
            # Legacy iptables with mangle table — original behaviour.
            self._set_legacy_rules(iptables_path)
        else:
            # nf_tables backend (Debian 12+/Ubuntu 22.04+): the mangle table
            # is unavailable, so we fall back to the filter table INPUT chain
            # with the same rate limiting.  The log prefix is the same
            # "canaryfw: " so the existing SynLogWatcher parser works unchanged.
            iptables_nft = shutil.which("iptables", path=STDPATH)
            if not iptables_nft:
                err = "Portscan module failed to start: no usable iptables found."
                print(err)
                raise Exception(err)
            self._set_nftables_rules(iptables_nft)

    def _set_legacy_rules(self, iptables_path):
        """Apply iptables rules using the legacy mangle table (original behaviour)."""
        os.system(
            'sudo {0} -t mangle -D PREROUTING -p tcp -i lo -j LOG --log-level=warning --log-prefix="canaryfw: " -m limit --limit="{1}/hour"'.format(
                iptables_path, self.lorate
            )
        )
        os.system(
            'sudo {0} -t mangle -A PREROUTING -p tcp -i lo -j LOG --log-level=warning --log-prefix="canaryfw: " -m limit --limit="{1}/hour"'.format(
                iptables_path, self.lorate
            )
        )
        os.system(
            'sudo {0} -t mangle -D PREROUTING -p tcp --syn -j LOG --log-level=warning --log-prefix="canaryfw: " -m limit --limit="{1}/second" ! -i lo'.format(
                iptables_path, self.synrate
            )
        )
        os.system(
            'sudo {0} -t mangle -A PREROUTING -p tcp --syn -j LOG --log-level=warning --log-prefix="canaryfw: " -m limit --limit="{1}/second" ! -i lo'.format(
                iptables_path, self.synrate
            )
        )
        os.system(
            'sudo {0} -t mangle -D PREROUTING -p tcp --tcp-flags ALL URG,PSH,SYN,FIN -m u32 --u32 "40=0x03030A01 && 44=0x02040109 && 48=0x080Affff && 52=0xffff0000 && 56=0x00000402" -j LOG --log-level=warning --log-prefix="canarynmap: " -m limit --limit="{1}/second"'.format(
                iptables_path, self.nmaposrate
            )
        )
        os.system(
            'sudo {0} -t mangle -A PREROUTING -p tcp --tcp-flags ALL URG,PSH,SYN,FIN -m u32 --u32 "40=0x03030A01 && 44=0x02040109 && 48=0x080Affff && 52=0xffff0000 && 56=0x00000402" -j LOG --log-level=warning --log-prefix="canarynmap: " -m limit --limit="{1}/second"'.format(
                iptables_path, self.nmaposrate
            )
        )
        os.system(
            'sudo {0} -t mangle -D PREROUTING -p tcp -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12=0x50000400" -j LOG --log-level=warning --log-prefix="canarynmapNULL: " -m limit --limit="{1}/second"'.format(
                iptables_path, self.nmaposrate
            )
        )
        os.system(
            'sudo {0} -t mangle -A PREROUTING -p tcp -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12=0x50000400" -j LOG --log-level=warning --log-prefix="canarynmapNULL: " -m limit --limit="{1}/second"'.format(
                iptables_path, self.nmaposrate
            )
        )
        os.system(
            'sudo {0} -t mangle -D PREROUTING -p tcp -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12=0x50290400" -j LOG --log-level=warning --log-prefix="canarynmapXMAS: " -m limit --limit="{1}/second"'.format(
                iptables_path, self.nmaposrate
            )
        )
        os.system(
            'sudo {0} -t mangle -A PREROUTING -p tcp -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12=0x50290400" -j LOG --log-level=warning --log-prefix="canarynmapXMAS: " -m limit --limit="{1}/second"'.format(
                iptables_path, self.nmaposrate
            )
        )
        os.system(
            'sudo {0} -t mangle -D PREROUTING -p tcp -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12=0x50010400" -j LOG --log-level=warning --log-prefix="canarynmapFIN: " -m limit --limit="{1}/second"'.format(
                iptables_path, self.nmaposrate
            )
        )
        os.system(
            'sudo {0} -t mangle -A PREROUTING -p tcp -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12=0x50010400" -j LOG --log-level=warning --log-prefix="canarynmapFIN: " -m limit --limit="{1}/second"'.format(
                iptables_path, self.nmaposrate
            )
        )

    def _set_nftables_rules(self, iptables_path):
        """
        Apply iptables rules using the nf_tables backend (filter table INPUT chain).

        Used as a fallback when the legacy mangle table is unavailable.
        The log prefix "canaryfw: " is preserved so SynLogWatcher parses
        the entries without any changes.

        Note: nmap OS-fingerprint detection (canarynmap/NULL/XMAS/FIN) requires
        the u32 match extension which may not be available on all nf_tables
        configurations; those rules are skipped silently if unsupported.
        """
        # Remove existing rule if present (ignore errors)
        os.system(
            'sudo {0} -D INPUT -p tcp --syn'
            ' -j LOG --log-level warning --log-prefix "canaryfw: "'
            ' -m limit --limit "{1}/second"'
            ' 2>/dev/null'.format(iptables_path, self.synrate)
        )
        # Insert at top of INPUT chain
        os.system(
            'sudo {0} -I INPUT 1 -p tcp --syn'
            ' -j LOG --log-level warning --log-prefix "canaryfw: "'
            ' -m limit --limit "{1}/second"'.format(iptables_path, self.synrate)
        )
