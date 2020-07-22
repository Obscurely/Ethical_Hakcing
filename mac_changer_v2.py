import subprocess
import optparse
import re

def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface]) #Store the output of the command
    mac_addres_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result) #Regex to get the mac address

    if mac_addres_search_result:
        return mac_addres_search_result.group(0) #Get the full first result
    else:
        return "[-] Could not read MAC address"

def change_mac(interface, mac):
    subprocess.call(["sudo", "ifconfig", interface, "down"])
    subprocess.call(["sudo", "ifconfig", interface, "hw", "ether", mac])
    subprocess.call(["sudo", "ifconfig", interface, "up"])
    print("[+] Changing MAC address for " + interface + " to " + mac)

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change it's MAC address") #Option to run
    parser.add_option("-m", "--mac", dest="mac", help="New MAC Address") #Option to run
    (options, arguments) = parser.parse_args() #To store the arguments and options
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    elif not options.mac:
        parser.error("[-] Please specify a new mac, use --help for more info.")
    return options

options = get_arguments()

current_mac = get_current_mac(options.interface)
print("Curent MAC = " + str(current_mac))

change_mac(options.interface, options.mac)

current_mac = get_current_mac(options.interface)

if current_mac == options.mac:
    print("[+] MAC address was succesfully changed to " + current_mac)
else:
    print("[-] MAC address did not get changed.")