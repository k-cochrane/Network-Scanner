#!usr/bin/env python
import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="The target IP address/range you wish to scan")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify an ip or ip range, use --help for more info")
    return options

def scan(ip):                                                                           #function to scan for devices
    arp_request = scapy.ARP(pdst=ip)                                                    #building ARP request packet with user defined ip range
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")                                    #building Ether packet to define the broadcast MAC
    arp_request_broadcast = broadcast/arp_request                                       #combining the ARP and Ether packets so they can be sent
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]       #sending packet to the broadcast MAC and capturing the resposes in two list(array) variables

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list                                                                 #produces a list of dictionaries with ip and mac addresses

def print_result(results_list):                                                         #function to print the results of the scan
    print("IP\t\t\tMAC Address\n--------------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])        

options = get_arguments()
scan_result = scan(options.target)                                                      #puts the clients_list created by the scan into the variable scan_result
print_result(scan_result)                                                               #sends the scan_result to be printed
