import threading
import time
import ipaddress
from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

# Configuration
ip_range_start = "192.168.1.2"  # Change to your desired IP range start
ip_range_end = "192.168.1.100"  # Change to your desired IP range end
subnet_mask = "255.255.255.0"
gateway = "192.168.1.254"  # Change to your network's gateway
dns_server = "8.8.8.8"  # Change to your network's DNS server
lease_time = 86400  # 1 day

# Global variables
binding_table = {}
offered_ips = set()

def get_next_available_ip():
    start = int(ipaddress.IPv4Address(ip_range_start))
    end = int(ipaddress.IPv4Address(ip_range_end))
    for ip_int in range(start, end + 1):
        ip_str = str(ipaddress.IPv4Address(ip_int))
        if ip_str not in offered_ips:
            return ip_str
    return None

def handle_dhcp_discover(pkt):
    print(f"Received DHCP DISCOVER from {pkt[Ether].src}")
    client_mac = pkt[Ether].src
    offered_ip = get_next_available_ip()
    if not offered_ip:
        print("No available IPs to offer.")
        return
    
    offered_ips.add(offered_ip)
    binding_table[client_mac] = offered_ip

    offer_pkt = (Ether(src=get_if_hwaddr(conf.iface), dst=pkt[Ether].src) /
                 IP(src="0.0.0.0", dst="255.255.255.255") /
                 UDP(sport=67, dport=68) /
                 BOOTP(op=2, yiaddr=offered_ip, siaddr=gateway, chaddr=pkt[BOOTP].chaddr) /
                 DHCP(options=[("message-type", "offer"),
                               ("subnet_mask", subnet_mask),
                               ("router", gateway),
                               ("name_server", dns_server),
                               ("lease_time", lease_time),
                               "end"]))

    sendp(offer_pkt)
    print(f"Sent DHCP OFFER to {client_mac} with IP {offered_ip}")

def handle_dhcp_request(pkt):
    print(f"Received DHCP REQUEST from {pkt[Ether].src}")
    client_mac = pkt[Ether].src
    requested_ip = pkt[BOOTP].yiaddr
    if client_mac in binding_table and binding_table[client_mac] == requested_ip:
        ack_pkt = (Ether(src=get_if_hwaddr(conf.iface), dst=pkt[Ether].src) /
                   IP(src="0.0.0.0", dst="255.255.255.255") /
                   UDP(sport=67, dport=68) /
                   BOOTP(op=2, yiaddr=requested_ip, siaddr=gateway, chaddr=pkt[BOOTP].chaddr) /
                   DHCP(options=[("message-type", "ack"),
                                 ("subnet_mask", subnet_mask),
                                 ("router", gateway),
                                 ("name_server", dns_server),
                                 ("lease_time", lease_time),
                                 "end"]))

        sendp(ack_pkt)
        print(f"Sent DHCP ACK to {client_mac} with IP {requested_ip}")
    else:
        print(f"IP {requested_ip} not available for {client_mac}")

def dhcp_packet_callback(pkt):
    if DHCP in pkt:
        dhcp_message_type = pkt[DHCP].options[0][1]
        if dhcp_message_type == 1:  # DHCP DISCOVER
            handle_dhcp_discover(pkt)
        elif dhcp_message_type == 3:  # DHCP REQUEST
            handle_dhcp_request(pkt)

def display_binding_table():
    while True:
        time.sleep(5)  # Adjust the sleep time as needed
        print("Binding Table:")
        for mac, ip in binding_table.items():
            print(f"MAC: {mac}, IP: {ip}")
        print("-" * 30)  # Separator for readability

def list_interfaces():
    """
    List all available network interfaces using Scapy.
    """
    print("Available interfaces:")
    for index, iface in enumerate(get_if_list()):
        print(f"Index: {index}, Name: {conf.ifaces[iface].name}")

if __name__ == "__main__":
    print("Starting DHCP server...")

    # List available interfaces
    list_interfaces()
    selected_index = input("Please enter the interface index you want to use: ")
    try:
        if selected_index.isdigit():
            selected_index = int(selected_index)
            if selected_index < len(conf.ifaces):
                selected_interface = list(conf.ifaces.keys())[selected_index]
                interface_name = conf.ifaces[selected_interface].name
                print(f"Using interface {interface_name} for DHCP Server.")
            else:
                raise IndexError("Invalid interface index selected.")
        else:
            raise ValueError("Invalid interface index selected.")
    except ValueError:
        print("Invalid input. Please enter a valid number.")
        exit(1)
    except IndexError as e:
        print(e)
        exit(1)

    # Start the binding table display thread
    display_thread = threading.Thread(target=display_binding_table)
    display_thread.daemon = True
    display_thread.start()

    # Start the DHCP server
    try:
        sniff(filter="udp and (port 67 or 68)", prn=dhcp_packet_callback, store=0)
    except Exception as e:
        print(f"An error occurred while sniffing: {e}")
