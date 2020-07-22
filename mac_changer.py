import subprocess

interface = input("Type the name of adapter: ")
mac = input("Type the mac address(xx:xx:xx:xx:xx:xx): ")

subprocess.call(["sudo", "ifconfig", interface, "down"]) #Close adapter
subprocess.call(["sudo", "ifconfig", interface, "hw", "ether", mac]) #Change mac
subprocess.call(["sudo", "ifconfig", interface, "up"]) #Open adapter

print("[+] Changed MAC address for {} to [{}]".format(interface, mac))