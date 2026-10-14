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

sniff(prn=show_packet, count=50)

print("\n--- SUMMARY ---")
print(f"Total bytes: {total_bytes}")

print("\nProtocols:")
for proto, count in protocol_counts.most_common():
    print(f"  {proto}: {count}")

print("\nTop talkers:")
for ip, count in talkers.most_common(5):
    print(f"  {ip}: {count} packets")