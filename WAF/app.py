from flask import Flask, jsonify
import threading
import pydivert
import logging
import joblib
import time
import ipaddress
import subprocess

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
        self.byte_count = 0
        self.packet_id = 123456

    def map_protocol(self, protocol):
        # Define a dictionary to map protocols to types
        protocol_map = {
            'TCP': '0',
            'UDP': '1',
            'CBR': '2',
        }

        # Use the dictionary to map the protocol to a type
        # If the protocol is not in the dictionary, return 'PING' as a default type
        return protocol_map.get(protocol, '3')

    def map_ip_to_node(self, ip_address):
        # Define a dictionary to map IP addresses to node names
        ip_node_map = {
            '192.168.1.1': 'Switch1',
            '192.168.1.2': 'Router',
            '192.168.1.3': 'server1',
            # Add more mappings as needed
        }

        # Use the dictionary to map the IP address to a node name
        # If the IP address is not in the dictionary, return the IP address as a default node name
        return ip_node_map.get(ip_address, ip_address)

    def calculate_average_packet_size(self):
        # Avoid division by zero
        if self.packet_count == 0:
            return 0
        return self.byte_count / self.packet_count

    import ipaddress

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
                    self.packet_id += 1
                    self.packet_count += 1
                    self.byte_count += len(packet.raw)
                    current_time = time.time()
                    elapsed_time = current_time - start_time

                    if elapsed_time >=1:
                        self.byte_count = self.byte_count / elapsed_time
                        self.packet_rate = self.packet_count / elapsed_time
                        logging.info(f"Packet rate: {self.packet_rate:.2f} packets/second")

                        self.packet_count = 0
                        start_time = current_time

                    # Extract features from packet for anomaly detection
                    features = self.extract_features(packet)
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
        # This function should be customized based on your feature extraction needs
        # Convert IP addresses to integers
        src_addr = int(ipaddress.ip_address(packet.src_addr))
        dst_addr = int(ipaddress.ip_address(packet.dst_addr))
        pkt_type = self.map_protocol(packet.protocol)  # Map the protocol to a type
        node_name_from = self.map_ip_to_node(packet.src_addr)
        node_name_to = self.map_ip_to_node(packet.dst_addr)
        avg_packet_size = self.calculate_average_packet_size()

        features = [
        src_addr,  # 'SRC_ADD'
        dst_addr,  # 'DES_ADD'
        self.packet_id,  # 'PKT_ID'
        0,  # 'FROM_NODE'
        0,  # 'TO_NODE'
        pkt_type,  # 'PKT_TYPE'
        len(packet.raw),  # 'PKT_SIZE'
        0,  # 'FLAGS'
        0,  # 'FID'
        0,  # 'SEQ_NUMBER'
        self.packet_count,  # 'NUMBER_OF_PKT'
        len(packet.raw),  # 'NUMBER_OF_BYTE'
        0,  # 'NODE_NAME_FROM'
        0,  # 'NODE_NAME_TO'
        0,  # 'PKT_IN'
        0,  # 'PKT_OUT'
        0,  # 'PKT_R'
        0,  # 'PKT_DELAY_NODE'
        self.packet_rate,  # 'PKT_RATE'
        self.byte_count,  # 'BYTE_RATE'
        avg_packet_size,  # 'PKT_AVG_SIZE'
        0,  # 'UTILIZATION'
        0,  # 'PKT_DELAY'
        0,  # 'PKT_SEND_TIME'
        0,  # 'PKT_RESEVED_TIME'
        # packet,  # 'FIRST_PKT_SENT'
        0,  # 'LAST_PKT_RESEVED'
        0   # 'PKT_CLASS'
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


