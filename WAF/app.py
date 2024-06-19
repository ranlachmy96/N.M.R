# from flask import Flask, request, jsonify
# import waf_rules
# import logging

# logging.basicConfig(filename='waf.log', level=logging.INFO, format='%(asctime)s %(message)s')

# def log_request(request, blocked):
#     status = "Blocked" if blocked else "Allowed"
#     logging.info(f"{status} request: {request.remote_addr} {request.method} {request.url} {request.data}")

# app = Flask(__name__)

# @app.route('/', methods=['GET', 'POST'])
# def index():
#     blocked = waf_rules.is_request_blocked(request)
#     log_request(request, blocked)
#     if blocked:
#         return jsonify({"message": "Request blocked by WAF"}), 403
#     return jsonify({"message": "Request allowed"}), 200

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5000)
# import pydivert
# def __init__(self):
#     self. w=pydivert.windivert(f"tcp.Dstport == {self.fake_port} and inbound") #or..
    
# def handle_syn_packet(self,packet):
#     session = TCPSession(self.asset_ip, self.fake_port, packet.src_addr,packet.src_port)
#     http_server = HTTPProxy((self.asset_ip,self.asset_port),(self.HP_ip,self.HP_port))
#     http_server.connect()
#     self.sessions[client_addr] = HTTPSession(packet, session, http_server)
    
# def packets_handler(self):
#     while self.running:
#         packet = self._w.recv()#recive packets from windivert driver
#         if packet.tcp.syn: self.handle_syn_packet(packet)

# def receive_syns(src_addr): #called by main
#     fltr = f"ip.SrcAddr == {src_addr} and tcp.Syn and tcp.DstPort == {self.fake_port} and inbound"
#     w = pydivert.windivert(fltr, priority=1)
#     w.open();time.sleep(30);w.close() #intercepting traffic for 30 seconds

# def get_new_threads(self):
#     return [threading.Thread(target=self.packets_handlers, daemon=True)]



################################################################################
# import pydivert
# import threading
# import time

# # Class to manage a TCP session
# class TCPSession:
#     def __init__(self, asset_ip, fake_port, src_addr, src_port):
#         self.asset_ip = asset_ip
#         self.fake_port = fake_port
#         self.src_addr = src_addr
#         self.src_port = src_port

# # Class to manage an HTTP proxy connection
# class HTTPProxy:
#     def __init__(self, asset_addr, hp_addr):
#         self.asset_addr = asset_addr
#         self.hp_addr = hp_addr

#     def connect(self):
#         # Logic to connect to the proxy server
#         pass

# # Class to manage an HTTP session
# class HTTPSession:
#     def __init__(self, packet, session, http_server):
#         self.packet = packet
#         self.session = session
#         self.http_server = http_server

# # Main class for the Web Application Firewall
# class WebApplicationFirewall:
#     def __init__(self, asset_ip, asset_port, fake_port, HP_ip, HP_port):
#         self.asset_ip = asset_ip
#         self.asset_port = asset_port
#         self.fake_port = fake_port
#         self.HP_ip = HP_ip
#         self.HP_port = HP_port
#         self.sessions = {}  # Dictionary to store sessions
#         self.running = True  # Flag to control the packet handler loop
#         self.w = pydivert.WinDivert(f"tcp.DstPort == {self.fake_port} and inbound")  # Initialize WinDivert with a filter

#     # Method to handle SYN packets
#     def handle_syn_packet(self, packet):
#         client_addr = (packet.src_addr, packet.src_port)  # Extract client address
#         session = TCPSession(self.asset_ip, self.fake_port, packet.src_addr, packet.src_port)  # Create a TCP session
#         http_server = HTTPProxy((self.asset_ip, self.asset_port), (self.HP_ip, self.HP_port))  # Create an HTTP proxy instance
#         http_server.connect()  # Connect to the HTTP proxy
#         self.sessions[client_addr] = HTTPSession(packet, session, http_server)  # Store the session

#     # Method to handle incoming packets
#     def packets_handler(self):
#         while self.running:
#             try:
#                 packet = self.w.recv()  # Receive packets from WinDivert driver
#                 if packet.tcp.syn:
#                     self.handle_syn_packet(packet)  # Handle SYN packets
#             except Exception as e:
#                 print(f"Error handling packet: {e}")

#     # Method to intercept SYN packets from any source address
#     def receive_syns(self):
#         try:
#             self.w.open()  # Open the WinDivert driver
#             time.sleep(30)  # Intercepting traffic for 30 seconds
#         finally:
#             self.w.close()  # Close the WinDivert driver

#     # Method to create new threads for packet handling
#     def get_new_threads(self):
#         return [threading.Thread(target=self.packets_handler, daemon=True)]  # Return a list of new threads

#     # Ensure the WinDivert handle is closed when no longer needed
#     def close(self):
#         if self.w:
#             self.w.close()

# # Example of usage:
# firewall = WebApplicationFirewall(
#     asset_ip="192.168.1.1",  # IP address of the router to be protected
#     asset_port=80,           # Port of the protected asset (typically HTTP port)
#     fake_port=8080,          # Fake port to intercept traffic
#     HP_ip="192.168.1.2",     # IP address of the HTTP proxy (your IP)
#     HP_port=8081             # Port of the HTTP proxy
# )

# try:
#     # Start packet handling in a new thread
#     thread = firewall.get_new_threads()[0]
#     thread.start()

#     # Intercept SYN packets directed to the router from any source address
#     firewall.receive_syns()
# finally:
#     # Ensure resources are cleaned up
#     firewall.close()
from flask import Flask, jsonify
import threading
import pydivert
import logging

# Configure logging
logging.basicConfig(filename='waf.log', level=logging.INFO, format='%(asctime)s %(message)s')

app = Flask(__name__)

# PacketSniffer class for sniffing packets
class PacketSniffer:
    def __init__(self, sniff_port):
        self.sniff_port = sniff_port
        self.running = True
        self.w = None
        self.lock = threading.Lock()

    def sniff_packets(self):
        while self.running:
            try:
                with self.lock:
                    if self.w is not None:
                        packet = self.w.recv()
                    else:
                        break
                if packet:
                    # Log specific details of the packet
                    logging.info(f"Packet from {packet.src_addr}:{packet.src_port} to {packet.dst_addr}:{packet.dst_port}")
                    logging.info(f"Packet length: {len(packet.raw)}")
                    logging.info(f"Packet data: {packet.payload}")
            except Exception as e:
                logging.error(f"Error handling packet: {e}")

    def start_sniffing(self):
        try:
            with self.lock:
                filter_str = f"tcp.DstPort == {self.sniff_port} and inbound"
                self.w = pydivert.WinDivert(filter_str)
                self.w.open()
                logging.info("WinDivert handle opened.")
        except Exception as e:
            logging.error(f"Error opening WinDivert handle: {e}")
        finally:
            if self.w:
                self.sniff_packets()
                self.w.close()
                logging.info("WinDivert handle closed.")

    def get_new_thread(self):
        return threading.Thread(target=self.start_sniffing, daemon=True)

    def stop_sniffing(self):
        self.running = False

# Initialize PacketSniffer for port 5000 (Flask's default port)
sniffer = PacketSniffer(sniff_port=5000)

# Endpoint for handling requests
@app.route('/', methods=['GET', 'POST'])
def index():
    blocked = False  # Placeholder, since you're only interested in packet sniffing
    if blocked:
        return jsonify({"message": "Request blocked by WAF"}), 403
    return jsonify({"message": "Request allowed"}), 200

# Main function to start Flask app and packet sniffing
if __name__ == '__main__':
    try:
        # Start packet sniffing in a new thread
        thread = sniffer.get_new_thread()
        thread.start()

        # Start Flask application
        app.run(debug=True, host='0.0.0.0', port=5000)

    finally:
        # Ensure packet sniffing is stopped when Flask application stops
        sniffer.stop_sniffing()


###############################################################################


