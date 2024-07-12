from flask import Flask, jsonify
import threading
import pydivert
import logging
import joblib
import time
import ipaddress
import subprocess
from datetime import datetime
import random



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
        self.w = None
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
        start_time = time.time()
        while self.running:
            try:
                with self.lock:
                    if self.w is not None:
                        packet = self.w.recv()
                    else:
                        break
                if packet:
                    current_time = time.time()
                    elapsed_time = current_time - start_time

                    if elapsed_time >=1:
                        self.packet_rate = self.packet_count / elapsed_time
                        logging.info(f"Packet rate: {self.packet_rate:.2f} packets/second")

                        self.packet_count = 0
                        start_time = current_time

                    # Extract features from packet for anomaly detection
                    features = self.extract_features(packet)
                    # print(packet)
                    features = scaler.transform([features])
                    prediction = model.predict(features)
                    if prediction == 1 or self.is_bogon(packet.src_addr):  # Assuming '1' indicates an anomaly
                        logging.warning(f"Anomaly detected from {packet.src_addr}:{packet.src_port}")

                        # Additional logic to handle the anomaly, e.g., port changing.
                        global current_port  # Replace with the new port you want to use
                        current_port += 1
                        subprocess.run(['node', '../nodeServer/portChanging/portChange.js', str(current_port)])
                        self.sniff_port = current_port
                    if self.is_bogon(packet.src_addr):
                        logging.warning(f"Packet from {packet.src_addr}:{packet.src_port} is a bogon address.")
                    else:
                        logging.info(f"Packet from {packet.src_addr}:{packet.src_port} is normal.")
                    # Log specific details of the packet
                    logging.info(f"Packet from {packet.src_addr}:{packet.src_port} to {packet.dst_addr}:{packet.dst_port}")
                    logging.info(f"Packet length: {len(packet.raw)}")
                    logging.info(f"Packet data: {packet.payload}")
            except Exception as e:
                logging.error(f"Error handling packet: {e}")

    def extract_features(self, packet):
        # Extract relevant features from the packet for the model
        # features = []

        PKT_TYPE_MAPPING = {
            'TCP': 1,
            'UDP': 2,
            'ACK': 3,
            'CBR': 4,
            'PING': 5
        }

        FLAGS_MAPPING = {
            '---A---': 1,
            '-------': 0
        }

        # Convert IP addresses to integers
        src_addr = int(ipaddress.ip_address(packet.src_addr).packed.hex(), 16)
        dst_addr = int(ipaddress.ip_address(packet.dst_addr).packed.hex(), 16)

        # Get packet type
        pkt_type = PKT_TYPE_MAPPING.get(packet.protocol, 0)

        # Get packet size
        pkt_size = len(packet.payload)

        # Get TCP flags if the packet is TCP
        flags = 0
        if packet.protocol == 'TCP':
            flags = FLAGS_MAPPING.get(packet.tcp_header.flags, 0)

        # Get sequence number if the packet is TCP
        seq_number = packet.tcp_header.seq_num if packet.protocol == 'TCP' else 0

        packet_id = ''.join(random.choice('123456789') for _ in range(2))

        # Build the features list
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


###############################################################################


