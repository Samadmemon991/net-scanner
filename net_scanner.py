#!/usr/bin/env python2

import scapy.all as scapy
import subprocess
import re

def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_broadcast_request = broadcast/arp_request
    #scapy.ls(scapy.Ether())
    #print(arp_broadcast_request.show())
    ans  = scapy.srp(arp_broadcast_request, timeout = 1, verbose= False)[0]
    print("IP\t\t\tMAC Addr")
    print(ip)
    print ("\n=============================================================\n")
    for element in ans:
        #print ("\n=============================================================\n")
        #print(element[1].show())
        print(element[1].psrc+"\t\t"+element[1].hwsrc)
        #print ("\n=============================================================\n")

def get_ip():
    ifconfig_result = subprocess.check_output(["ifconfig"]).decode()
    current_mac = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.", ifconfig_result)
                          #(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    if (not current_mac):
        print("[-] cannot read ip addr")
    else:
        #print(current_mac.group(0))
        return(current_mac.group(0))




scan(str(get_ip())+"1/24")

#scan("192.168.0.1/24")
#scan("10.11.13.00/24")

#for x in range(100):
 #   scan("192.168.43."+str(x))

