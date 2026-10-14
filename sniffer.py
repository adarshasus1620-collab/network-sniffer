import argparse
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP

protocol_counts = Counter()
talkers = Counter()
total_bytes = 0

def show_packet(packet):
    global total_bytes

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            proto = "OTHER"
            sport = dport = "-"

        protocol_counts[proto] += 1
        talkers[src] += 1
        total_bytes += size

        print(f"[{proto}] {src}:{sport} -> {dst}:{dport} ({size} bytes)")

def print_summary():
    print("\n--- SUMMARY ---")
    print(f"Total bytes: {total_bytes}")

    print("\nProtocols:")
    for proto, count in protocol_counts.most_common():
        print(f"  {proto}: {count}")

    print("\nTop talkers:")
    for ip, count in talkers.most_common(5):
        print(f"  {ip}: {count} packets")

def parse_args():
    parser = argparse.ArgumentParser(description="Simple network packet sniffer")
    parser.add_argument("-c", "--count", type=int, default=50,
                        help="number of packets to capture (0 = until Ctrl+C)")
    parser.add_argument("-f", "--filter", default=None,
                        help='BPF filter, e.g. "tcp port 443" or "udp"')
    parser.add_argument("-i", "--interface", default=None,
                        help="network interface to sniff on")
    return parser.parse_args()

def main():
    args = parse_args()
    print(f"[*] Capturing... count={args.count or 'unlimited'}, filter={args.filter or 'none'}")

    try:
        sniff(prn=show_packet, count=args.count, filter=args.filter,
              iface=args.interface, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")

    print_summary()

if __name__ == "__main__":
    main()