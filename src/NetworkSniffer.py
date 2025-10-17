from scapy.all import sniff, get_if_list

class NetworkSniffer:
    def __init__(self):
        self.packets = []
        self.is_running = False
        self.packet_count = 0
        self.oshibka = False

    def _process_packet(self, packet):
        if not self.is_running:
            return None
        

    def start(self, packet_count, interface):
        if not self.check_interface(interface): 
            print(f"\nche ta ne rabotaet, problema tyt {interface}\n")
            return False
        try:
            self.is_running = True
            sniff(count = packet_count, 
                  iface = interface,
                  prn = self._process_packet)
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


    def stop(self):
        self.is_running = False
        print("tutu")

if __name__ == "__main__":
   a = NetworkSniffer()
   a.start(4, 'llw0')
   print(get_if_list())


   
    
        