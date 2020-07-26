#Python 2
import scapy.all as scapy
import re
import argparse

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip) #Pdst is IPField and is set to equal the parameter
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #Mac field
    arp_request_broadcast = broadcast/arp_request #Combined request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #Final request without junk *verbose = False*

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet) #iface = the interface, store = store or not store infromation in the memory, prn = call back function

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print("[+] You are under attack!")
        except IndexError:
            pass
                
sniff("eth0")