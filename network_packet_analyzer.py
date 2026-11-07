
# CODSOFT TASK 1
# Network Packet Analyzer using Python

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# Function to analyze each packet
def analyze_packet(packet):

    print("\n========== PACKET DETAILS ==========")

    # Check whether the packet contains IP information
    if IP in packet:

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        print("Source IP      :", source_ip)
        print("Destination IP :", destination_ip)

        # Identify the protocol
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other IP Protocol"

        print("Protocol       :", protocol)

        # Display packet size
        print("Packet Size    :", len(packet), "bytes")

        # Display TCP port information
        if TCP in packet:
            print("Source Port    :", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        # Display UDP port information
        elif UDP in packet:
            print("Source Port    :", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        # Display available packet data
        if Raw in packet:
            data = packet[Raw].load
            print("Packet Data    :", repr(data[:100]))
        else:
            print("Packet Data    : No application data found")

    else:
        print("This packet does not contain an IP layer.")

    print("====================================")


# Main program
print("====================================")
print("     NETWORK PACKET ANALYZER")
print("====================================")

print("Starting packet capture...")
print("Press Ctrl+C in the terminal to stop.")

try:
    # Capture 10 packets from the selected interface
    sniff(
        prn=analyze_packet,
        count=10,
        store=False
    )

    print("\nPacket capture completed.")

except KeyboardInterrupt:
    print("\nPacket capture stopped by user.")

except Exception as error:
    print("\nError:", error)
    print("Check your permissions and packet capture setup.")
