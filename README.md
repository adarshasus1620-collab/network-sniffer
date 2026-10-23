# Network Packet Sniffer

A command-line network packet sniffer built in Python with Scapy. I built it step by step to learn how network traffic works.

## Features

- Live packet capture with BPF filters (for example "tcp port 443")
- Supports TCP, UDP, ICMP and ARP
- DNS query logging: shows which domain names a device asks for
- Port scan detection: alerts when one IP hits many ports quickly
- Summary report: protocol counts, top talkers, top ports, top conversations
- Hex and ASCII payload preview
- Quiet mode with a live packet counter
- Save captures to CSV or to .pcap (opens in Wireshark)

## Setup

1. Install Python 3 and Scapy:

```
pip install scapy
```

2. On Windows, install [Npcap](https://npcap.com) and tick "Install Npcap in WinPcap API-compatible Mode".
3. Open your terminal as Administrator (packet capture needs it on Windows). On Linux or macOS, use `sudo`.

## Usage

```
python sniffer.py                          # capture 50 packets
python sniffer.py -c 100                   # capture 100 packets
python sniffer.py -c 0                     # capture until Ctrl+C
python sniffer.py -f "tcp port 443"        # BPF filter
python sniffer.py -p                       # show hex and ASCII payload
python sniffer.py -q                       # quiet mode with live counter
python sniffer.py -o capture.csv           # save to CSV
python sniffer.py -w capture.pcap          # save to pcap (Wireshark)
python sniffer.py -h                       # show all options
```

## Options

| Option | What it does |
|---|---|
| `-c` | number of packets (0 = until Ctrl+C) |
| `-f` | BPF filter |
| `-i` | network interface |
| `-p` | payload preview |
| `-q` | quiet mode |
| `-o` | CSV output file |
| `-w` | pcap output file |

## Legal and ethical notice

Only capture traffic on networks and devices you own or have explicit permission to monitor. Unauthorized packet capture may be illegal.