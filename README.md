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

## Legal and ethical notice

Only capture traffic on networks and devices you own or have explicit permission to monitor. Unauthorized packet capture may be illegal.