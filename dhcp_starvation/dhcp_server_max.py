import threading
import time
import ipaddress
from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

# **************************************************************************************
# Configuration parameters for the DHCP server.
# **************************************************************************************
ip_range_start = "192.168.1.2"  
ip_range_end = "192.168.1.100"  
subnet_mask = "255.255.255.0"
gateway = "192.168.1.254"  
dns_server = "8.8.8.8"  
lease_time = 86400  
max_requests_per_second = 10  

# **************************************************************************************
# Initialize the binding table and set of offered IP addresses.
# **************************************************************************************
binding_table = {}
offered_ips = set()
dhcp_server_running = True
request_counts = {}
max_binding_table_size = int(ipaddress.IPv4Address(ip_range_end)) - int(ipaddress.IPv4Address(ip_range_start)) + 1

# Initialize a lock for thread synchronization
lock = threading.Lock()

# **************************************************************************************
# Function to get the next available IP address in the configured range.
# **************************************************************************************
def get_next_available_ip():
    start = int(ipaddress.IPv4Address(ip_range_start))
    end = int(ipaddress.IPv4Address(ip_range_end))
    for ip_int in range(start, end + 1):
        ip_str = str(ipaddress.IPv4Address(ip_int))
        if ip_str not in offered_ips:
            return ip_str
    return None

# **************************************************************************************
# Function to clear the binding table and offered IP addresses.
# **************************************************************************************
def clear_binding_table():
    with lock:
        binding_table.clear()
        offered_ips.clear()
    print("Binding table cleared.")

# **************************************************************************************
# Function to handle incoming DHCP DISCOVER packets. 
# With an added check if the binding table is full.
# **************************************************************************************
def handle_dhcp_discover(pkt):
    with lock:
        client_mac = pkt[Ether].src
        if request_counts.get(client_mac, 0) >= max_requests_per_second:
            print(f"Rate limit exceeded for {client_mac}")
            return
        request_counts[client_mac] = request_counts.get(client_mac, 0) + 1
    
        if len(binding_table) >= max_binding_table_size:
            print("Binding table is full. Clearing table.")
            clear_binding_table()

    print(f"Received DHCP DISCOVER from {client_mac}")
    offered_ip = get_next_available_ip()
    if not offered_ip:
        print("No available IPs to offer.")
        return
    
    with lock:
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

# **************************************************************************************
# Function to handle incoming DHCP REQUEST packets.
# **************************************************************************************
def handle_dhcp_request(pkt):
    with lock:
        client_mac = pkt[Ether].src
        if request_counts.get(client_mac, 0) >= max_requests_per_second:
            print(f"Rate limit exceeded for {client_mac}")
            return
        request_counts[client_mac] = request_counts.get(client_mac, 0) + 1
    
    print(f"Received DHCP REQUEST from {client_mac}")
    requested_ip = pkt[BOOTP].yiaddr
    with lock:
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


# **************************************************************************************
# Callback function for sniffing DHCP packets.
# **************************************************************************************
def dhcp_packet_callback(pkt):
    if dhcp_server_running:
        if DHCP in pkt:
            dhcp_message_type = pkt[DHCP].options[0][1]
            if dhcp_message_type == 1:  
                handle_dhcp_discover(pkt)
            elif dhcp_message_type == 3:  
                handle_dhcp_request(pkt)

# **************************************************************************************
# Function to continuously display the current binding table.
# **************************************************************************************
def display_binding_table():
    while dhcp_server_running:
        time.sleep(5)  
        print("Binding Table:")
        with lock:
            for mac, ip in binding_table.items():
                print(f"MAC: {mac}, IP: {ip}")
        print("-" * 30)

# **************************************************************************************
# Function to list all available network interfaces using Scapy.
# **************************************************************************************
def list_interfaces():
    print("Available interfaces:")
    for index, iface in enumerate(get_if_list()):
        print(f"Index: {index}, Name: {conf.ifaces[iface].name}")

# **************************************************************************************
# Function to reset the rate limit counters periodically.
# Reset rate limit counters every second.
# **************************************************************************************
def reset_rate_limit():
    while dhcp_server_running:
        time.sleep(1)
        with lock:
            request_counts.clear()

# **************************************************************************************
# Main function to start the DHCP server.
# **************************************************************************************
if __name__ == "__main__":
    print("Starting DHCP server...")

    
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

    # Start a background thread to display the binding table.
    display_thread = threading.Thread(target=display_binding_table)
    display_thread.daemon = True
    display_thread.start()

    # Start a background thread to reset the rate limit counters.
    rate_limit_thread = threading.Thread(target=reset_rate_limit)
    rate_limit_thread.daemon = True
    rate_limit_thread.start()

    # Start sniffing for DHCP packets on the selected interface.
    try:
        sniff(filter="udp and (port 67 or 68)", prn=dhcp_packet_callback, store=0)
    except Exception as e:
        print(f"An error occurred while sniffing: {e}")
