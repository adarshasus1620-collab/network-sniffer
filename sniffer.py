import argparse
import csv
import time
from collections import Counter, defaultdict
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, DNS, DNSQR

protocol_counts = Counter()
talkers = Counter()
total_bytes = 0
args = None
csv_writer = None
port_hits = defaultdict(dict)
alerted = set()
SCAN_PORTS = 15
SCAN_WINDOW = 10
port_counts = Counter()
conversations = Counter()

def hex_preview(data, width=16, max_bytes=64):
    data = data[:max_bytes]
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {hex_part:<{width * 3}} {ascii_part}")
    return "\n".join(lines)
def check_port_scan(src, dport):
    now = time.time()
    hits = port_hits[src]
    hits[dport] = now

    for port in list(hits):
        if now - hits[port] > SCAN_WINDOW:
            del hits[port]

    if len(hits) > SCAN_PORTS and src not in alerted:
        alerted.add(src)
        print(f"\n[!] ALERT: possible port scan from {src} "
              f"({len(hits)} ports in {SCAN_WINDOW}s)\n")

def log_dns_query(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        if packet[DNS].qr == 0:
            name = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
            src = packet[IP].src
            print(f"[DNS] {src} asked for: {name}")

def show_packet(packet):
    global total_bytes
    if ARP in packet:
        op = "who-has" if packet[ARP].op == 1 else "is-at"
        protocol_counts["ARP"] += 1
        total_bytes += len(packet)
        print(f"[ARP] {packet[ARP].psrc} {op} {packet[ARP].pdst}")
        return

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if packet[TCP].flags == "S":
                check_port_scan(src, dport)
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            if dport == 53:
                log_dns_query(packet)
        elif ICMP in packet:
            proto = "ICMP"
            sport = dport = "-"
        else:
            proto = "OTHER"
            sport = dport = "-"

        protocol_counts[proto] += 1
        talkers[src] += 1
        total_bytes += size
        conversations[(src, dst)] += 1
        if dport != "-":
            port_counts[dport] += 1

        print(f"[{proto}] {src}:{sport} -> {dst}:{dport} ({size} bytes)")

        if csv_writer:
            csv_writer.writerow([datetime.now().isoformat(), proto, src, dst, sport, dport, size])

        if args.payload and Raw in packet:
            print(hex_preview(bytes(packet[Raw].load)))

def print_summary():
    print("\n--- SUMMARY ---")
    print(f"Total bytes: {total_bytes}")

    print("\nProtocols:")
    for proto, count in protocol_counts.most_common():
        print(f"  {proto}: {count}")

    print("\nTop talkers:")
    for ip, count in talkers.most_common(5):
        print(f"  {ip}: {count} packets")

    print("\nTop destination ports:")
    for port, count in port_counts.most_common(5):
        print(f"  {port}: {count} packets")

    print("\nTop conversations:")
    for (src, dst), count in conversations.most_common(5):
        print(f"  {src} -> {dst}: {count} packets")

def parse_args():
    parser = argparse.ArgumentParser(description="Simple network packet sniffer")
    parser.add_argument("-c", "--count", type=int, default=50,
                        help="number of packets to capture (0 = until Ctrl+C)")
    parser.add_argument("-f", "--filter", default=None,
                        help='BPF filter, e.g. "tcp port 443" or "udp"')
    parser.add_argument("-i", "--interface", default=None,
                        help="network interface to sniff on")
    parser.add_argument("-p", "--payload", action="store_true",
                        help="show hex + ASCII preview of packet payloads")
    parser.add_argument("-o", "--output", default=None,
                        help="save captured packets to a CSV file")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="hide packet lines, show a live counter instead")
    return parser.parse_args()

def main():
    global args, csv_writer
    args = parse_args()
    print(f"[*] Capturing... count={args.count or 'unlimited'}, filter={args.filter or 'none'}")

    csv_file = None
    if args.output:
        csv_file = open(args.output, "w", newline="")
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["timestamp", "protocol", "src", "dst", "sport", "dport", "size"])

    try:
        sniff(prn=show_packet, count=args.count, filter=args.filter,
              iface=args.interface, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
    finally:
        if csv_file:
            csv_file.close()
            print(f"[*] Saved to {args.output}")

    print_summary()

if __name__ == "__main__":
    main()