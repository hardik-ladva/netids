# NetIDS — Network Packet Analyzer / Mini-IDS

A Python tool for real-time packet capture, protocol parsing, and structured logging.
Built as part of the Terra YSWS program.

## Setup

```bash
# 1. Create a virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run (requires root/admin for raw socket access)
sudo python capture.py            # Linux / macOS
# Windows: run terminal as Administrator, then:
python capture.py
```

## Usage

```bash
# Basic capture (logs JSON + CSV to /logs/)
sudo python capture.py

# Capture only TCP traffic
sudo python capture.py -f "tcp"

# Capture on a specific interface, 100 packets, JSON only
sudo python capture.py -i eth0 -c 100 --fmt json

# Capture DNS queries only
sudo python capture.py -f "udp port 53"
```

## Output

Each run creates timestamped files in `logs/`:
- `capture_YYYYMMDD_HHMMSS.json` — full structured records
- `capture_YYYYMMDD_HHMMSS.csv`  — flat table, easy to open in Excel/pandas

### JSON record shape
```json
{
  "timestamp": "2026-10-08T14:30:01Z",
  "protocol":  "TCP",
  "src_ip":    "192.168.1.5",
  "dst_ip":    "142.250.80.46",
  "src_port":  54321,
  "dst_port":  443,
  "length":    74,
  "flags":     ["SYN"],
  "dns_query": null
}
```

## Phase roadmap
- [x] Phase 1 — Live capture, protocol parsing, JSON/CSV logging
- [ ] Phase 2 — Port scan detection, brute-force detection, MITRE ATT&CK tagging
- [ ] Phase 3 — Flask dashboard with live alerts
- [ ] Phase 4 — PDF/CSV report export, write-up
