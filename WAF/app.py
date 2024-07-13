from flask import Flask, jsonify
import threading
import logging
import joblib
import time
import ipaddress
import subprocess
from datetime import datetime
import random
from scapy.all import sniff, TCP, IP

# Configure logging
logging.basicConfig(filename='waf.log', level=logging.INFO, format='%(asctime)s %(message)s')

app = Flask(__name__)

model = joblib.load('../anamolyDetector/model.joblib')
scaler = joblib.load('../anamolyDetector/scaler.joblib')
current_port = 3000

# PacketSniffer class for sniffing packets
class PacketSniffer:
    def __init__(self, sniff_port):
        self.sniff_port = sniff_port
        self.running = True
        self.lock = threading.Lock()
        self.packet_count = 0
        self.packet_rate = 0

    def is_bogon(self, ip):
        try:
            return (not ipaddress.ip_address(ip).is_loopback and
                    not ipaddress.ip_address(ip).is_private and
                    (ipaddress.ip_address(ip).is_reserved or
                     ipaddress.ip_address(ip).is_multicast))
        except ValueError:
            return False

    def sniff_packets(self):
        print("Starting packet sniffing...")  # Debug print to indicate sniffing has started

        def packet_handler(packet):
            start_time = time.time()
            with self.lock:
                self.packet_count += 1
                current_time = time.time()
                elapsed_time = current_time - start_time

                if elapsed_time >= 1:
                    self.packet_rate = self.packet_count / elapsed_time
                    logging.info(f"Packet rate: {self.packet_rate:.2f} packets/second")

                    self.packet_count = 0
                    start_time = current_time

                # Log packet details
                if IP in packet and TCP in packet:
                    logging.info(f"Sniffed packet: {packet.summary()}")

                    # Extract features from packet for anomaly detection
                    features = self.extract_features(packet)
                    features = scaler.transform([features])
                    prediction = model.predict(features)
                    if prediction == 1 or self.is_bogon(packet[IP].src):
                        logging.warning(f"Anomaly detected from {packet[IP].src}:{packet[TCP].sport}")

                        # Additional logic to handle the anomaly, e.g., port changing.
                        global current_port
                        current_port += 1
                        subprocess.run(['node', '../nodeServer/portChanging/portChange.js', str(current_port)])
                        self.sniff_port = current_port
                    if self.is_bogon(packet[IP].src):
                        logging.warning(f"Packet from {packet[IP].src}:{packet[TCP].sport} is a bogon address.")
                    else:
                        logging.info(f"Packet from {packet[IP].src}:{packet[TCP].sport} is normal.")
                    # Log specific details of the packet
                    logging.info(f"Packet from {packet[IP].src}:{packet[TCP].sport} to {packet[IP].dst}:{packet[TCP].dport}")
                    logging.info(f"Packet length: {len(packet)}")
                    logging.info(f"Packet data: {packet[TCP].payload}")

        # Start sniffing packets with a general filter
        sniff(prn=packet_handler, store=0, stop_filter=lambda x: not self.running)

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
            '': 0    # No flag
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

        features = [
            src_addr,
            dst_addr,
            packet_id,
            src_addr,
            dst_addr,
            pkt_type,
            pkt_size,
            flags,
            0,
            seq_number,
            1,
            pkt_size,
            src_addr,
            dst_addr,
            0,
            0,
            0,
            0,
            0,
            0,
            pkt_size,
            0,
            0,
            datetime.now().timestamp(),
            datetime.now().timestamp(),
            datetime.now().timestamp(),
            datetime.now().timestamp(),
        ]

        return features

    def get_new_thread(self):
        return threading.Thread(target=self.sniff_packets, daemon=True)

    def stop_sniffing(self):
        self.running = False

# Initialize PacketSniffer for port 3000 (Node's default port)
sniffer = PacketSniffer(sniff_port=current_port)

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
