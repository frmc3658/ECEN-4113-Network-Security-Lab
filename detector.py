from scapy.all import PcapReader
from scapy.all import TCP, IP, Ether, Raw
import sys


def process_pcap(pcap_fname):
    # Dictionaries for IP tracking
    synDict = {}
    synAckDict = {}

    for packet in PcapReader(pcap_fname):
        if packet.haslayer(TCP) and packet.haslayer(IP):
            # Check for just SYN
            if packet[TCP].flags == 'S':
                srcIP = packet[IP].src

                # Increment SYN count for IP
                if srcIP in synDict:
                    synDict[srcIP] += 1
                else:
                    synDict[srcIP] = 1
                    synAckDict[srcIP] = 1
            # Otherwise check for SYN+ACK
            elif packet[TCP].flags == 'SA':
                srcIP = packet[IP].dst

                # Increment SYN+ACK count for IP
                if srcIP in synAckDict:
                    synAckDict[srcIP] += 1
                else:
                    synAckDict[srcIP] = 1

    # Detect possible SYN scans
    suspiciousIPs = []

    for srcIP, synPackets in synDict.items():
        # If the sourvce IP is in the SYN+ACK dictionary...
        if srcIP in synAckDict:
            synAckPackets = synAckDict[srcIP]

            if synPackets > (3 * synAckPackets):
                suspiciousIPs.append(srcIP)

    # Print the suspicious IP addresses
    suspiciousIPs.sort()

    for ip in suspiciousIPs:
        print(ip)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Use: python3 detector.py file.pcap')
        sys.exit(-1)
    process_pcap(sys.argv[1])
