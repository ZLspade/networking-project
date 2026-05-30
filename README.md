# Python Packet Sniffer

A modular, command-line network packet sniffer built with [Scapy](https://scapy.net/). Captures live traffic, filters by protocol, logs to CSV, and optionally displays a real-time top-talkers dashboard.

Built as a portfolio project to demonstrate practical understanding of the OSI model, raw socket programming, and Python software design.

---

## How It Works — OSI Layer Walkthrough

| Module | OSI Layer | What it touches |
|--------|-----------|-----------------|
| `capture.py` | L2 Data Link | Reads the raw Ethernet frame via Scapy |
| `capture.py` | L3 Network | Extracts source & destination IP addresses from the IP header |
| `capture.py` | L4 Transport | Reads TCP/UDP headers for port numbers and protocol type |
| `capture.py` | L7 Application | Inspects TCP payloads on port 80/8080/8000 to detect HTTP |
| `filter.py` | L3 / L4 / L7 | Decides whether a packet passes the active protocol filter |
| `logger.py` | (above L7) | Persists structured packet metadata to disk as CSV |
| `dashboard.py` | L3 / L4 | Aggregates traffic by IP address and protocol |
| `sniffer.py` | — | CLI glue: wires all modules together and drives Scapy's `sniff()` |

The journey of a single packet through this tool:

```
NIC → Scapy (raw socket) → capture.py (parse L2-L7)
    → filter.py (keep or drop)
    → sniffer.py (print to terminal)
    → logger.py (append to CSV)
    → dashboard.py (update counters)
```

---

## Project Structure

```
packet-sniffer/
├── sniffer.py        # CLI entry point — run this
├── capture.py        # Packet parsing across OSI L2–L7
├── filter.py         # Protocol filter (all / tcp / udp / http)
├── logger.py         # CSV logger (thread-safe, append mode)
├── dashboard.py      # Top-talkers dashboard using collections.Counter
├── requirements.txt  # Python dependencies
└── README.md
```

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Python 3.8+ | |
| **Windows only** — [Npcap](https://npcap.com/) | Scapy requires this instead of WinPcap. Download and install the free version. |
| **Linux/Mac only** — `libpcap` | Usually pre-installed. If not: `sudo apt install libpcap-dev` |
| Administrator / root privileges | Raw socket capture requires elevated permissions on all platforms. |

---

## Installation

```bash
# 1. Clone or download the project
cd packet-sniffer

# 2. (Recommended) create a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux / Mac

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

> **Windows:** open your terminal as **Administrator** before running.  
> **Linux/Mac:** prefix commands with `sudo`.

```bash
python sniffer.py [OPTIONS]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i`, `--interface` | auto | Network interface to listen on (e.g. `"Wi-Fi"`, `eth0`) |
| `-f`, `--filter` | `all` | Protocol filter: `all`, `tcp`, `udp`, or `http` |
| `-c`, `--count` | `0` | Number of packets to capture (`0` = run until Ctrl+C) |
| `-o`, `--output` | `packets.csv` | CSV file to write captured packets to |
| `-d`, `--dashboard` | off | Show live top-talkers dashboard every 20 packets |

### Examples

```bash
# Capture all protocols until Ctrl+C
python sniffer.py

# Capture 100 TCP packets on the Wi-Fi interface
python sniffer.py -i "Wi-Fi" -f tcp -c 100

# Capture HTTP traffic with the live dashboard
python sniffer.py -f http -d

# Save to a custom file
python sniffer.py -o my_capture.csv -c 500

# Show help
python sniffer.py --help
```

### Example terminal output

```
[*] Packet sniffer started
    Interface : default
    Filter    : HTTP
    Output    : packets.csv
    Count     : unlimited
    Dashboard : on
    Press Ctrl+C to stop

[2026-05-23 14:02:11] HTTP  192.168.1.5:54321     -> 142.250.80.46:80     len=512
  HTTP GET /search?q=scapy+tutorial HTTP/1.1
[2026-05-23 14:02:11] HTTP  142.250.80.46:80      -> 192.168.1.5:54321    len=1420
  HTTP HTTP/1.1 200 OK
```

---

## CSV Output

Each captured packet is appended as one row:

| Column | Example | Description |
|--------|---------|-------------|
| `timestamp` | `2026-05-23 14:02:11` | Capture time |
| `protocol` | `HTTP` | Detected protocol (TCP / UDP / HTTP / OTHER) |
| `src_ip` | `192.168.1.5` | Source IP (OSI L3) |
| `src_port` | `54321` | Source port (OSI L4) |
| `dst_ip` | `142.250.80.46` | Destination IP (OSI L3) |
| `dst_port` | `80` | Destination port (OSI L4) |
| `length` | `512` | Total packet length in bytes |
| `payload_preview` | `GET /search HTTP/1.1` | First line of HTTP message (HTTP only) |

---

## Dashboard

Enable with `-d`. Prints a summary every 20 matched packets and again on exit:

```
────────────────────────────────────────────────────
  Live snapshot — 20 packets captured
────────────────────────────────────────────────────
Top source IPs      (Layer 3)
  1. 192.168.1.5          12 ( 60.0%)  ████████████
  2. 10.0.0.1              8 ( 40.0%)  ████████
Top destination IPs (Layer 3)
  1. 142.250.80.46        15 ( 75.0%)  ███████████████
Protocols           (Layer 4)
  1. HTTP                 18 ( 90.0%)  ██████████████████
  2. TCP                   2 ( 10.0%)  ██
────────────────────────────────────────────────────
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `PermissionError` / `Operation not permitted` | Run as Administrator (Windows) or `sudo` (Linux/Mac) |
| `ImportError: No module named 'scapy'` | Run `pip install -r requirements.txt` inside your virtualenv |
| No packets captured on Windows | Install [Npcap](https://npcap.com/) and restart your terminal |
| Wrong interface | Run `python -c "from scapy.all import *; print(get_if_list())"` to list available interfaces |
