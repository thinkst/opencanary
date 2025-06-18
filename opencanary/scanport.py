from scapy.all import sniff, TCP, IP
from datetime import datetime
import json

CANARY_PORTS = [21, 22, 23, 80, 110, 139, 443, 445, 3306, 3389, 8080, 5900]
LOG_CODES = {
    'SYN': 5001,
    'OS': 5002,
    'NULL': 5003,
    'XMAS': 5004,
    'FIN': 5005
}
LOG_PATH = '/app/opencanary.log'  # Chemin du log (doit matcher le -v du docker run)

def detect_scan_flags(pkt):
    if not pkt.haslayer(TCP): return
    tcp = pkt[TCP]
    try:
        src = pkt[IP].src
        dst = pkt[IP].dst
    except:
        # fallback pour IPv6 ou erreurs Scapy (rare)
        return
    sport, dport = tcp.sport, tcp.dport
    if dport not in CANARY_PORTS:
        return
    flags = int(tcp.flags)
    logtype, scan_type = None, None

    if flags == 0:
        logtype = LOG_CODES['NULL']
        scan_type = "NULL"
    elif flags == 1:
        logtype = LOG_CODES['FIN']
        scan_type = "FIN"
    elif flags == 41:
        logtype = LOG_CODES['XMAS']
        scan_type = "XMAS"
    elif flags == 2:
        logtype = LOG_CODES['SYN']
        scan_type = "SYN"
    else:
        return

    event = {
        "src_host": src,
        "src_port": sport,
        "dst_host": dst,
        "dst_port": dport,
        "logtype": logtype,
        "scan_type": scan_type,
        "local_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"),
        "logdata": {"msg": f"Scan {scan_type} détecté sur port {dport} depuis {src}"}
    }

    with open(LOG_PATH, 'a') as f:
        f.write(json.dumps(event) + "\n")
    print(f"Logged: {scan_type} scan from {src} to port {dport}")

print("== scanport.py démarré (sniff TCP flags) ==")
sniff(filter="tcp", prn=detect_scan_flags, store=0)
