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
                dst = packet[IP].dst

                # Increment SYN+ACK count for IP
                if dst in synAckDict:
                    synAckDict[dst] += 1
                else:
                    synAckDict[dst] = 1

    # Detect possible SYN scans
    suspiciousIPs = []

    for ip, synPackets in synDict.items():
        if ip in synAckDict:
            synAckPackets = synAckDict[ip]

            # Packet reached threshold of SYN+ACK
            if synPackets >= (3 * synAckPackets):
                suspiciousIPs.append(ip)
            # Packet is in the SYN dict, but not SYN+ACK dict
            elif synAckPackets is None:
                suspiciousIPs.append(ip)

    # Print the suspicious IP addresses
    for ip in suspiciousIPs:
        print(ip)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Use: python3 detector.py file.pcap')
        sys.exit(-1)
    process_pcap(sys.argv[1])
