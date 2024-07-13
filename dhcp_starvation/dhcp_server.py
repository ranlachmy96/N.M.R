from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether

# Configuration for the DHCP server
server_ip = "192.168.1.1"  # IP address of the DHCP server
subnet_mask = "255.255.255.0"
router = "192.168.1.1"
dns_server = "8.8.8.8"
pool_start = "192.168.1.100"
pool_end = "192.168.1.200"
leases = {}

def ip_to_int(ip):
    return int.from_bytes(socket.inet_aton(ip), byteorder='big')

def int_to_ip(ip_int):
    return socket.inet_ntoa(ip_int.to_bytes(4, byteorder='big'))

def get_next_ip(pool_start, pool_end, leases):
    start = ip_to_int(pool_start)
    end = ip_to_int(pool_end)
    for ip_int in range(start, end + 1):
        ip = int_to_ip(ip_int)
        if ip not in leases.values():
            return ip
    return None

def handle_dhcp(packet):
    if DHCP in packet and packet[DHCP].options[0][1] == 1:  # DHCP Discover
        client_mac = packet[Ether].src
        offer_ip = get_next_ip(pool_start, pool_end, leases)
        if offer_ip:
            leases[client_mac] = offer_ip
            send_offer(packet, offer_ip)
        else:
            print("No available IP addresses in the pool.")

    elif DHCP in packet and packet[DHCP].options[0][1] == 3:  # DHCP Request
        client_mac = packet[Ether].src
        requested_ip = packet[DHCP].options[2][1]
        if requested_ip in leases.values():
            send_ack(packet, requested_ip)
        else:
            send_nak(packet)

def send_offer(packet, offer_ip):
    offer_packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(conf.iface)) / \
                   IP(src=server_ip, dst="255.255.255.255") / \
                   UDP(sport=67, dport=68) / \
                   BOOTP(op=2, yiaddr=offer_ip, siaddr=server_ip, chaddr=packet[BOOTP].chaddr) / \
                   DHCP(options=[("message-type", "offer"),
                                 ("server_id", server_ip),
                                 ("subnet_mask", subnet_mask),
                                 ("router", router),
                                 ("lease_time", 600),
                                 ("renewal_time", 300),
                                 ("rebinding_time", 450),
                                 ("end")])
    sendp(offer_packet, iface=conf.iface)

def send_ack(packet, client_ip):
    ack_packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(conf.iface)) / \
                 IP(src=server_ip, dst="255.255.255.255") / \
                 UDP(sport=67, dport=68) / \
                 BOOTP(op=2, yiaddr=client_ip, siaddr=server_ip, chaddr=packet[BOOTP].chaddr) / \
                 DHCP(options=[("message-type", "ack"),
                               ("server_id", server_ip),
                               ("subnet_mask", subnet_mask),
                               ("router", router),
                               ("lease_time", 600),
                               ("renewal_time", 300),
                               ("rebinding_time", 450),
                               ("end")])
    sendp(ack_packet, iface=conf.iface)

def send_nak(packet):
    nak_packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(conf.iface)) / \
                 IP(src=server_ip, dst="255.255.255.255") / \
                 UDP(sport=67, dport=68) / \
                 BOOTP(op=2, siaddr=server_ip, chaddr=packet[BOOTP].chaddr) / \
                 DHCP(options=[("message-type", "nak"),
                               ("server_id", server_ip),
                               ("end")])
    sendp(nak_packet, iface=conf.iface)


def list_interfaces():
    """
    List all available network interfaces using Scapy.
    """
    print("Available interfaces:")
    for index, iface in enumerate(conf.ifaces):
        print(f"Index: {index}, Name: {conf.ifaces[iface].name}")

# Start the DHCP server
if __name__ == "__main__":
    list_interfaces()
    selected_index = input("Please enter the interface index you want to use: ")

    if selected_index.isdigit():
        selected_index = int(selected_index)
        if selected_index < len(conf.ifaces):
            selected_interface = list(conf.ifaces.keys())[selected_index]
            interface_name = conf.ifaces[selected_interface].name
            print(f"Using interface {interface_name} for DHCP Starvation attack.")
            # dhcp_starvation(target_ip, interface_name)
            print("Starting DHCP server...")
            sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp, iface=interface_name)
        else:
            print("Invalid interface index selected.")
    else:
        print("Invalid input. Please enter a valid interface index.")

