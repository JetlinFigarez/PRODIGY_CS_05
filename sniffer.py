from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        protocol = "OTHER"
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"

        print(f"[{protocol}] {ip_src} -> {ip_dst}")

sniff(prn=process_packet, store=False)
