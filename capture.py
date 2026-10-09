"""
Phase 1 – Network Packet Analyzer / Mini-IDS
capture.py — live capture + structured logging
"""

import json
import csv
import datetime
import argparse
import os
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
except ImportError:
    print("[!] Scapy not installed. Run: pip install scapy")
    raise SystemExit(1)

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# ─── helpers ──────────────────────────────────────────────────────────────────

def ts():
    return datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"

def get_protocol(pkt):
    if pkt.haslayer(TCP):  return "TCP"
    if pkt.haslayer(UDP):  return "UDP"
    if pkt.haslayer(ICMP): return "ICMP"
    return "OTHER"

def get_flags(pkt):
    if not pkt.haslayer(TCP):
        return None
    flags = pkt[TCP].flags
    names = {0x02:"SYN", 0x10:"ACK", 0x01:"FIN", 0x04:"RST", 0x08:"PSH", 0x20:"URG"}
    return [v for k, v in names.items() if flags & k]

def parse_dns(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        try:
            return pkt[DNSQR].qname.decode().rstrip(".")
        except Exception:
            pass
    return None

def build_record(pkt):
    record = {
        "timestamp": ts(),
        "protocol":  get_protocol(pkt),
        "src_ip":    None,
        "dst_ip":    None,
        "src_port":  None,
        "dst_port":  None,
        "length":    len(pkt),
        "flags":     None,
        "dns_query": None,
    }
    if pkt.haslayer(IP):
        record["src_ip"] = pkt[IP].src
        record["dst_ip"] = pkt[IP].dst
    if pkt.haslayer(TCP):
        record["src_port"] = pkt[TCP].sport
        record["dst_port"] = pkt[TCP].dport
        record["flags"]    = get_flags(pkt)
    elif pkt.haslayer(UDP):
        record["src_port"] = pkt[UDP].sport
        record["dst_port"] = pkt[UDP].dport
    record["dns_query"] = parse_dns(pkt)
    return record

# ─── loggers ──────────────────────────────────────────────────────────────────

class JSONLogger:
    def __init__(self, path):
        self.path = path
        self.records = []

    def write(self, record):
        self.records.append(record)
        with open(self.path, "w") as f:
            json.dump(self.records, f, indent=2)

class CSVLogger:
    FIELDS = ["timestamp","protocol","src_ip","dst_ip",
              "src_port","dst_port","length","flags","dns_query"]

    def __init__(self, path):
        self.path = path
        self._wrote_header = False

    def write(self, record):
        row = {**record, "flags": "|".join(record["flags"]) if record["flags"] else ""}
        mode = "a"
        with open(self.path, mode, newline="") as f:
            w = csv.DictWriter(f, fieldnames=self.FIELDS)
            if not self._wrote_header:
                w.writeheader()
                self._wrote_header = True
            w.writerow(row)

# ─── stats tracker ────────────────────────────────────────────────────────────

class Stats:
    def __init__(self):
        self.total   = 0
        self.by_proto = defaultdict(int)
        self.top_src  = defaultdict(int)

    def update(self, r):
        self.total += 1
        self.by_proto[r["protocol"]] += 1
        if r["src_ip"]:
            self.top_src[r["src_ip"]] += 1

    def summary(self):
        top = sorted(self.top_src.items(), key=lambda x: x[1], reverse=True)[:5]
        lines = [
            f"\n{'─'*50}",
            f"  Packets captured : {self.total}",
            f"  Breakdown        : { dict(self.by_proto) }",
            f"  Top sources      : { top }",
            f"{'─'*50}",
        ]
        return "\n".join(lines)

# ─── main capture loop ────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="NetIDS – Phase 1 packet capture")
    ap.add_argument("-i", "--iface",  default=None,   help="Network interface (default: auto)")
    ap.add_argument("-c", "--count",  type=int, default=0, help="Packets to capture (0 = infinite)")
    ap.add_argument("-f", "--filter", default="ip",   help="BPF filter string (default: ip)")
    ap.add_argument("--fmt", choices=["json","csv","both"], default="both",
                    help="Log format (default: both)")
    args = ap.parse_args()

    stamp    = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    loggers  = []
    if args.fmt in ("json", "both"):
        loggers.append(JSONLogger(f"{LOG_DIR}/capture_{stamp}.json"))
        print(f"[+] JSON log  → {LOG_DIR}/capture_{stamp}.json")
    if args.fmt in ("csv", "both"):
        loggers.append(CSVLogger(f"{LOG_DIR}/capture_{stamp}.csv"))
        print(f"[+] CSV log   → {LOG_DIR}/capture_{stamp}.csv")

    stats = Stats()

    def handle(pkt):
        r = build_record(pkt)
        for lg in loggers:
            lg.write(r)
        stats.update(r)

        proto = r["protocol"]
        src   = f"{r['src_ip']}:{r['src_port']}"  if r["src_port"] else r["src_ip"]
        dst   = f"{r['dst_ip']}:{r['dst_port']}"  if r["dst_port"] else r["dst_ip"]
        flags = f" [{','.join(r['flags'])}]" if r["flags"] else ""
        dns   = f" DNS→{r['dns_query']}"    if r["dns_query"] else ""
        print(f"  {r['timestamp']}  {proto:<5}  {str(src):<25} → {str(dst):<25}{flags}{dns}")

    print(f"\n[*] Starting capture  interface={args.iface or 'auto'}  "
          f"filter='{args.filter}'  count={args.count or '∞'}")
    print(f"    Press Ctrl+C to stop.\n")
    print(f"  {'TIMESTAMP':<22}  {'PROTO':<5}  {'SOURCE':<25}   {'DESTINATION':<25}")
    print(f"  {'─'*22}  {'─'*5}  {'─'*25}   {'─'*25}")

    try:
        sniff(iface=args.iface, filter=args.filter,
              prn=handle, count=args.count, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\n[!] Permission denied. Run with sudo: sudo python capture.py")
        raise SystemExit(1)

    print(stats.summary())
    print("[+] Capture complete. Logs saved.\n")

if __name__ == "__main__":
    main()
