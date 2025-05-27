# Python-Packet-Sniffer-with-Scapy

from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    print("="*60)
    if IP in packet:
        ip_layer = packet[IP]
        print(f"[IP] {ip_layer.src} -> {ip_layer.dst}")
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"[TCP] Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"[UDP] Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")
        elif ICMP in packet:
            print("[ICMP] Packet detected")

        print(f"Payload: {bytes(packet.payload).decode('utf-8', errors='ignore')[:100]}")
    else:
        print("Non-IP Packet Type:", packet.summary())

# Start sniffing on the default network interface
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
