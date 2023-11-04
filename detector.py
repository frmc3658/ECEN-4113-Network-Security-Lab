from scapy.all import PcapReader
from scapy.all import TCP, IP, Ether, Raw
import sys

def process_pcap(pcap_fname):
    # Dictionary to keep track of SYN and SYN+ACK packets count for each source IP
    synCount = {}
    synAckCount = {}

    for packet in PcapReader(pcap_fname):
        if Ether in packet and IP in packet and TCP in packet:

            # Check for SYN+ACK
            if (packet[TCP].flags & 0x02) and (packet[TCP].flags & 0x10):
                srcIP = packet[IP].src

                # Increment SYN+ACK count for IP
                if srcIP in synAckCount:
                    synAckCount[srcIP] += 1
                else:
                    synAckCount[srcIP] = 1
            # Otherwise check for just SYN
            elif packet[TCP].flags & 0x02:
                srcIP = packet[IP].src

                # Increment SYN count for IP
                if srcIP in synCount:
                    synCount[srcIP] += 1
                else:
                    synCount[srcIP] = 1
                    synAckCount[srcIP] = 1

    # Detect possible SYN scans
    suspiciousIPs = []

    for srcIP, synPackets in synCount.items():
        if srcIP in synAckCount:
            synAckPackets = synAckCount[srcIP]

            if synPackets > (3 * synAckPackets):
                suspiciousIPs.append(srcIP)

    # Print the suspicious IP addresses
    for ip in suspiciousIPs:
        print(ip)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Use: python3 detector.py file.pcap')
        sys.exit(-1)
    process_pcap(sys.argv[1])
