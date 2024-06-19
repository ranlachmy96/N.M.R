import pydivert
import threading
import time

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
                    print(packet)
            except Exception as e:
                print(f"Error handling packet: {e}")

    def start_sniffing(self):
        try:
            with self.lock:
                filter_str = f"tcp.DstPort == {self.sniff_port} and inbound"
                self.w = pydivert.WinDivert(filter_str)
                self.w.open()
                print("WinDivert handle opened.")
        except Exception as e:
            print(f"Error opening WinDivert handle: {e}")
        finally:
            if self.w:
                self.sniff_packets()
                self.w.close()
                print("WinDivert handle closed.")

    def get_new_thread(self):
        return threading.Thread(target=self.start_sniffing, daemon=True)

    def stop_sniffing(self):
        self.running = False

if __name__ == '__main__':
    sniffer = PacketSniffer(sniff_port=80)  # Replace 80 with the port you want to sniff
    try:
        thread = sniffer.get_new_thread()
        thread.start()
        time.sleep(30)  # Sniff packets for 30 seconds
    finally:
        sniffer.stop_sniffing()
