from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    """Callback function to process each packet."""
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Determine protocol
        if protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        else:
            proto_name = str(protocol)

        print(f"IP Packet: {ip_src} -> {ip_dst} (Protocol: {proto_name})")

        # Print payload if it's TCP or UDP
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[IP].payload)
            print(f"Payload: {payload}")

def main():
    """Main function to start the packet sniffer."""
    # Start sniffing (you may need to run this with administrative privileges)
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
