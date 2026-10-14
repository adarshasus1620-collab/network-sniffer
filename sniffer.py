from scapy.all import sniff

def show_packet(packet):
    print(packet.summary())

sniff(prn=show_packet, count=10)