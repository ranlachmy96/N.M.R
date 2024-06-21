from flask import Flask, jsonify
import threading
import pydivert
import logging
import joblib

# Configure logging
logging.basicConfig(filename='waf.log', level=logging.INFO, format='%(asctime)s %(message)s')

app = Flask(__name__)

model = joblib.load('../anamolyDetector/model.joblib')
scaler = joblib.load('../anamolyDetector/scaler.joblib')

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
                    # Extract features from packet for anomaly detection
                    features = self.extract_features(packet)
                    features = scaler.transform([features])
                    prediction = model.predict(features)
                    if prediction == 1:  # Assuming '1' indicates an anomaly
                        logging.warning(f"Anomaly detected from {packet.src_addr}:{packet.src_port}")
                        # Additional logic to handle the anomaly, e.g., block the IP, etc.
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
        features = [
        0,  # 'SRC_ADD'
        0,  # 'DES_ADD'
        0,  # 'PKT_ID'
        0,  # 'FROM_NODE'
        0,  # 'TO_NODE'
        0,  # 'PKT_TYPE'
        len(packet.raw),  # 'PKT_SIZE'
        0,  # 'FLAGS'
        0,  # 'FID'
        0,  # 'SEQ_NUMBER'
        0,  # 'NUMBER_OF_PKT'
        0,  # 'NUMBER_OF_BYTE'
        0,  # 'NODE_NAME_FROM'
        0,  # 'NODE_NAME_TO'
        0,  # 'PKT_IN'
        0,  # 'PKT_OUT'
        0,  # 'PKT_R'
        0,  # 'PKT_DELAY_NODE'
        0,  # 'PKT_RATE'
        0,  # 'BYTE_RATE'
        0,  # 'PKT_AVG_SIZE'
        0,  # 'UTILIZATION'
        0,  # 'PKT_DELAY'
        0,  # 'PKT_SEND_TIME'
        0,  # 'PKT_RESEVED_TIME'
        0,  # 'FIRST_PKT_SENT'
        # 0,  # 'LAST_PKT_RESEVED'
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

# Initialize PacketSniffer for port 5000 (Flask's default port)
sniffer = PacketSniffer(sniff_port=3000)

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


