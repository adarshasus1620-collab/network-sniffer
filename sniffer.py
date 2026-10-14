from scapy.all import sniff, IP, TCP, UDP

def show_packet(packet):
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

        print(f"[{proto}] {src}:{sport} -> {dst}:{dport} ({size} bytes)")

sniff(prn=show_packet, count=10)