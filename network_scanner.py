import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP/ IP range.") #Runtime argument
    options = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip) #Pdst is IPField and is set to equal the parameter
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #Mac field
    arp_request_broadcast = broadcast/arp_request #COmbined request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #Final request without junk *verbose = False*

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc} #Clean store to a variable
        clients_list.append(client_dict)
    return clients_list

def print_result(result_list):
    print("IP\t\t\tMAC Address\n------------------------------------------")
    for client in result_list:
        print(client["ip"], end="\t\t")
        print(client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)