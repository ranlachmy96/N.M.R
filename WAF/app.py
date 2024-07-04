from flask import Flask, jsonify
import threading
import pydivert
import logging
import joblib
import time
import ipaddress
import subprocess
from scapy.all import IP, TCP, UDP, Raw
from datetime import datetime



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

    def is_bogon(self,ip):
        try:
            return (ipaddress.ip_address(ip).is_private or
                    ipaddress.ip_address(ip).is_reserved or
                    ipaddress.ip_address(ip).is_multicast)
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
                    print(features)
                    features = scaler.transform([features])
                    prediction = model.predict(features)
                    if prediction == 1:  # Assuming '1' indicates an anomaly
                        logging.warning(f"Anomaly detected from {packet.src_addr}:{packet.src_port}")

                        # Additional logic to handle the anomaly, e.g., port changing.
                        global current_port  # Replace with the new port you want to use
                        current_port += 1
                        subprocess.run(['node', '../nodeServer/portChanging/portChange.js', str(current_port)])
                    # if self.is_bogon(packet.src_addr):
                    #     logging.warning(f"Packet from {packet.src_addr}:{packet.src_port} is a bogon address.")
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
        features = {}
        featuress = []

        PKT_TYPE_MAPPING = {
            'tcp': 1,
            'udp': 2,
            'ack': 3,
            'cbr': 4,
            'ping': 5
        }

        FLAGS_MAPPING = {
            '---A---': 1,
            '-------': 0
        }

        NODE_NAME_MAPPING = {name: i for i, name in enumerate([
            'Switch1', 'Router', 'server1', 'router', 'clien-4', 'client-2', 'Switch2', 'client-5', 'clien-9',
            'clien-2',
            'clien-1', 'clien-14', 'clien-5', 'clien-11', 'clien-13', 'clien-0', 'switch1', 'client-4', 'clienthttp',
            'clien-7', 'clien-19', 'client-14', 'clien-12', 'clien-8', 'clien-15', 'webserverlistin', 'client-18',
            'client-1', 'switch2', 'clien-6', 'client-10', 'client-7', 'webcache', 'clien-10', 'client-15', 'clien-3',
            'client-17', 'client-16', 'clien-17', 'clien-18', 'client-12', 'client-8', 'client-0', 'clien-16',
            'client-13',
            'client-11', 'client-6', 'client-3', 'client-9', 'client-19', 'http_client'
        ])}

        scapy_packet = IP(packet.raw)

        features['SRC_ADD'] = int(ipaddress.ip_address(scapy_packet.src).packed.hex(), 16)
        features['DES_ADD'] = int(ipaddress.ip_address(scapy_packet.dst).packed.hex(), 16)

        if scapy_packet.haslayer(TCP) or scapy_packet.haslayer(UDP):
            transport_layer = scapy_packet[TCP] if scapy_packet.haslayer(TCP) else scapy_packet[UDP]
            featuress = [
                int(ipaddress.ip_address(scapy_packet.src).packed.hex(), 16),
                int(ipaddress.ip_address(scapy_packet.dst).packed.hex(), 16),
                scapy_packet.id,
                int(ipaddress.ip_address(scapy_packet.src).packed.hex(), 16),
                int(ipaddress.ip_address(scapy_packet.dst).packed.hex(), 16),
                PKT_TYPE_MAPPING.get(transport_layer.name.lower(), 0),
                len(packet.raw),
                FLAGS_MAPPING.get(str(transport_layer.flags), 0) if scapy_packet.haslayer(TCP) else 0,
                0,
                transport_layer.seq if scapy_packet.haslayer(TCP) else 0,
                1,
                len(packet.raw),
                NODE_NAME_MAPPING.get(scapy_packet.src, 0),
                NODE_NAME_MAPPING.get(scapy_packet.dst, 0),
                0,
                0,
                0,
                0,
                0,
                0,
                len(packet.raw),
                0,
                0,
                datetime.now().timestamp(),
                datetime.now().timestamp(),
                datetime.now().timestamp(),
                datetime.now().timestamp()
            ]

            features['FROM_NODE'] = int(ipaddress.ip_address(scapy_packet.src).packed.hex(), 16)
            features['TO_NODE'] = int(ipaddress.ip_address(scapy_packet.dst).packed.hex(), 16)
            features['PKT_ID'] = scapy_packet.id
            features['PKT_TYPE'] = PKT_TYPE_MAPPING.get(transport_layer.name.lower(), 0)
            features['PKT_SIZE'] = len(packet.raw)
            features['FLAGS'] = FLAGS_MAPPING.get(str(transport_layer.flags), 0) if scapy_packet.haslayer(TCP) else 0
            features['FID'] = 0
            features['SEQ_NUMBER'] = transport_layer.seq if scapy_packet.haslayer(TCP) else 0
            features['NUMBER_OF_PKT'] = 1
            features['NUMBER_OF_BYTE'] = len(packet.raw)
            features['NODE_NAME_FROM'] = NODE_NAME_MAPPING.get(scapy_packet.src, 0)
            features['NODE_NAME_TO'] = NODE_NAME_MAPPING.get(scapy_packet.dst, 0)
            features['PKT_IN'] = 0
            features['PKT_OUT'] = 0
            features['PKT_R'] = 0
            features['PKT_DELAY_NODE'] = 0
            features['PKT_RATE'] = 0
            features['BYTE_RATE'] = 0
            features['PKT_AVG_SIZE'] = len(packet.raw)
            features['UTILIZATION'] = 0
            features['PKT_DELAY'] = 0
            features['PKT_SEND_TIME'] = datetime.now().timestamp()
            features['PKT_RESEVED_TIME'] = datetime.now().timestamp()
            features['FIRST_PKT_SENT'] = datetime.now().timestamp()
            features['LAST_PKT_RESEVED'] = datetime.now().timestamp()

        return featuress
            # [features.get(key, 0) for key in [
        #     'SRC_ADD', 'DES_ADD', 'PKT_ID', 'FROM_NODE', 'TO_NODE', 'PKT_TYPE', 'PKT_SIZE', 'FLAGS', 'FID',
        #     'SEQ_NUMBER', 'NUMBER_OF_PKT', 'NUMBER_OF_BYTE', 'NODE_NAME_FROM', 'NODE_NAME_TO', 'PKT_IN', 'PKT_OUT',
        #     'PKT_R', 'PKT_DELAY_NODE', 'PKT_RATE', 'BYTE_RATE', 'PKT_AVG_SIZE', 'UTILIZATION', 'PKT_DELAY',
        #     'PKT_SEND_TIME', 'PKT_RESEVED_TIME', 'FIRST_PKT_SENT', 'LAST_PKT_RESEVED'
        # ]]

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


