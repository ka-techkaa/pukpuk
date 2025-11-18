from scapy.all import sniff, get_if_list, IP, TCP, UDP
import time
import threading 
from collections import defaultdict

class NetworkSniffer:
    def __init__(self):
        self.packets = []
        self.is_running = False
        self.packet_count = 1
        self.oshibka = False
        self.sniffer_thread = None

        self.protocol_stats = defaultdict(int)

    def set_new_packet_callback(self, callback):
        self.new_packet_callback = callback

    def _process_packet(self, packet):
        if not self.is_running:
            return None

        packet_info ={
            'no': self.packet_count,
            'source': 'Unknown',
            'destination': 'Unknown',
            'protocol': 'Unknown',
            'length': len(packet),
            'time': time.strftime("%H:%M:%S", time.localtime())
        }

        if packet.haslayer(IP):
            ip = packet[IP]
            packet_info['source'] = ip.src
            packet_info['destination'] = ip.dst
            if packet.haslayer(TCP):
                packet_info['protocol'] = "TCP"
                self.packet_count += 1
                self.packets.append(packet_info)
                self.protocol_stats['TCP'] += 1
                if hasattr(self, 'new_packet_callback'):
                    self.new_packet_callback(packet_info)
            elif packet.haslayer(UDP):
                packet_info['protocol'] = "UDP"
                self.packet_count += 1
                self.packets.append(packet_info)
                self.protocol_stats['UDP'] += 1
                if hasattr(self, 'new_packet_callback'):
                    self.new_packet_callback(packet_info)


    def start(self, packet_count = None, interface=None):
        if self.is_running:
            return False
        if not self.check_interface(interface) and interface != None: 
            print(f"\nche ta ne rabotaet, problema tyt {interface}\n")
            return False
        try:
            self.is_running = True

            if packet_count != None:
                 sniff(count = packet_count, 
                    iface = interface,
                    prn = self._process_packet)
            else:
                self.sniffer_thread = threading.Thread(
                    target = self._sniff_packets,
                    args = (interface, self._process_packet),
                    daemon = True 
                )
                self.sniffer_thread.start()

            print("zapusk") 
            return True
        except Exception as e:
            print(f"hfhfhhf{e}")

    def check_interface(self, iface):
        if iface in self.get_available_interface():
            return True
        return False

    def get_available_interface(self):
        try: 
            available_interfaces = get_if_list()
            return available_interfaces
        except Exception as e:
            print(f"gfgff{e}")
        return []
    
    def _sniff_packets(self, iface, prn):
        sniff(
            iface = iface,
            prn = prn)


    def stop(self):
        self.is_running = False
        if self.sniffer_thread != None:
            self.sniffer_thread.join(timeout=2.0)
        print("tutu")

    def get_statistics(self):
        return {
            'total_packets': self.packet_count,
            'protocols': dict(self.protocol_stats) 
        }

    def clear_capture(self):
        self.packets = []
        self.packet_count = 0 
        self.protocol_stats.clear()

if __name__ == "__main__":
    a = NetworkSniffer()
    a.start()
    time.sleep(5.0)
    a.stop()
    print(a.packets)
       
        