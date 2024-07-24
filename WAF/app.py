from flask import Flask, jsonify
import threading
import logging
import joblib
import time
import ipaddress
import subprocess
from datetime import datetime
import random
from scapy.all import sniff, TCP, IP, get_if_list, get_if_hwaddr
from scapy.layers.inet import ICMP, UDP

# **************************************************************************************
# Configure logging to record events and anomalies.
# **************************************************************************************
logging.basicConfig(filename='waf.log', level=logging.INFO, format='%(asctime)s %(message)s')

app = Flask(__name__)

# **************************************************************************************
# Load trained anomaly detection model and scaler
# **************************************************************************************
model = joblib.load('../anamolyDetector/model.joblib')
scaler = joblib.load('../anamolyDetector/scaler.joblib')
current_port = 3000


# **************************************************************************************
# PacketSniffer class to handle packet sniffing and anomaly detection.
# By Logging the packet details
# Extracting features from packet for anomaly detection
# Add Additional logic to handle the anomaly, e.g., port changing.
# **************************************************************************************
class PacketSniffer:
    def __init__(self, sniff_port):
        self.sniff_port = sniff_port
        self.running = True
        self.lock = threading.Lock()
        self.packet_count = 0
        self.packet_rate = 0
        self.current_time = 0

    def is_bogon(self, ip):
        try:
            return (not ipaddress.ip_address(ip).is_loopback and
                    not ipaddress.ip_address(ip).is_private and
                    (ipaddress.ip_address(ip).is_reserved or
                     ipaddress.ip_address(ip).is_multicast))
        except ValueError:
            return False

    def sniff_packets(self):
        print("Starting packet sniffing...")  

        def packet_handler(packet):
            packet_type = "Unknown"
            src_addr = "N/A"
            dst_addr = "N/A"
            sport = "N/A"
            dport = "N/A"

            if IP in packet:
                packet_type = "IP"
                src_addr = packet[IP].src
                dst_addr = packet[IP].dst
                if TCP in packet:
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    packet_type += "/TCP"
                elif UDP in packet:
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    packet_type += "/UDP"
            elif ICMP in packet:
                packet_type = "ICMP"

            start_time = time.time()
            with self.lock:
                self.packet_count += 1
                self.current_time = time.time()
                elapsed_time = self.current_time - start_time

                if elapsed_time >= 1:
                    self.packet_rate = self.packet_count / elapsed_time
                    logging.info(f"Packet rate: {self.packet_rate:.2f} packets/second")

                    self.packet_count = 0
                    start_time = self.current_time

                logging.info(f"Sniffed packet: {packet.summary()}")

                if IP in packet:
                    features = self.extract_features(packet)
                    features = scaler.transform([features])
                    prediction = model.predict(features)
                    if prediction == 1 or self.is_bogon(packet[IP].src) or len(packet) > 60000:
                        logging.warning(f"Anomaly detected from {src_addr}")

                        
                        global current_port
                        # For blocking IP addresses or ports
                        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                        "name=BlockInboundPort{0}".format(current_port), "dir=in", "action=block",
                                        "protocol=TCP", "localport={0}".format(current_port)])
                        current_port += 1
                        subprocess.run(['node', '../nodeServer/portChanging/portChange.js', str(current_port)])
                        self.sniff_port = current_port

                    if self.is_bogon(packet[IP].src):
                        logging.warning(f"{packet_type} Packet from {src_addr} is a bogon address.")
                    else:
                        logging.info(f"{packet_type} Packet from {src_addr} is normal.")

                    # Log specific details of the packet
                    logging.info(f"{packet_type} Packet from {src_addr}:{sport} to {dst_addr}:{dport}")
                logging.info(f"Packet length: {len(packet)}")
                logging.info(f"Packet data: {packet.payload}")

        # List available interfaces and select the appropriate one
        interfaces = get_if_list()

        # Try to identify the loopback interface
        loopback_interface = None
        for iface in interfaces:
            if "loopback" in iface.lower() or "npf_loopback" in iface.lower():
                loopback_interface = iface
                break

        if loopback_interface is None:
            print("Loopback interface not found. Please check your interfaces.")
            return

        # Start sniffing packets without a specific filter to capture all packets
        sniff(prn=packet_handler, store=0, iface=loopback_interface, stop_filter=lambda x: not self.running)

    def extract_features(self, packet):
        PKT_TYPE_MAPPING = {
            'TCP': 1,
            'UDP': 2,
            'ACK': 3,
            'CBR': 4,
            'PING': 5
        }

        FLAGS_MAPPING = {
            'A': 1,  # ACK flag
            '': 0  # No flag
        }

        src_addr = int(ipaddress.ip_address(packet[IP].src).packed.hex(), 16)
        dst_addr = int(ipaddress.ip_address(packet[IP].dst).packed.hex(), 16)
        pkt_type = PKT_TYPE_MAPPING.get(packet[IP].proto, 0)
        pkt_size = len(packet[IP].payload)
        flags = 0
        if TCP in packet:
            flags = FLAGS_MAPPING.get(packet[TCP].flags, 0)
        seq_number = packet[TCP].seq if TCP in packet else 0
        packet_id = ''.join(random.choice('123456789') for _ in range(2))
        fid = ''.join(random.choice('123456789') for _ in range(2))
        time_diff = time.time() - self.current_time
        time_diff = time_diff * 100000
        formatted_time = "{:.6f}".format(time_diff)
        now = time.time() - self.current_time
        formatted_now = "{:.6f}".format(now)
        suspected_attack = 0  #normal

        if packet.payload and len(packet.payload) > 60000:
            suspected_attack = 1

        features = [
            src_addr,
            dst_addr,
            packet_id,
            src_addr,
            dst_addr,
            pkt_type,
            pkt_size,
            flags,
            fid,
            seq_number,
            self.packet_count,
            pkt_size,
            src_addr,
            dst_addr,
            0,
            0,
            0,
            0,
            self.packet_rate,
            0,
            pkt_size,
            0,
            formatted_time,
            formatted_now,
            formatted_time,
            formatted_now,
            suspected_attack,
        ]

        return features

    def get_new_thread(self):
        return threading.Thread(target=self.sniff_packets, daemon=True)

    def stop_sniffing(self):
        self.running = False


# Initialize PacketSniffer for port 3000 (Node's default port)
sniffer = PacketSniffer(sniff_port=current_port)


# **************************************************************************************
# Flask endpoint to handle requests.
# **************************************************************************************
@app.route('/', methods=['GET', 'POST'])
def index():
    blocked = False  
    if blocked:
        return jsonify({"message": "Request blocked by WAF"}), 403
    return jsonify({"message": "Request allowed"}), 200


# **************************************************************************************
# Main function to start Flask app and packet sniffing.
# **************************************************************************************
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
