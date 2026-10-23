import sniffer

for port in range(1, 10):
    sniffer.check_port_scan("1.2.3.4", port)