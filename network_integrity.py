# Install a LAN tap, listen with a host on the lan tap, capture the traffic on the lan tap and on the tapped host self.
# Let the script compare and ensure system/network integrity 

import hashlib
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict


class VerifyNetwork:
    
    def __init__(self):
        self.source_ip = input("Pass the source IP:")
        self.lan_tap = "lan_tap.pcap"
        self.computer_trace = "network_trace.pcap"

    def load_packets(self, pcap_file):
        packets = rdpcap(pcap_file)
        return packets

    def generate_packet_hash(self, packet, src_ip):
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            if ip_layer.src == src_ip:
                tcp_layer = packet.getlayer(TCP)
                udp_layer = packet.getlayer(UDP)
                dst = ip_layer.dst
                payload = bytes(packet.payload)
                sport, dport = None, None
                if tcp_layer:
                    sport, dport = tcp_layer.sport, tcp_layer.dport
                elif udp_layer:
                    sport, dport = udp_layer.sport, udp_layer.dport
                packet_data = f"{ip_layer.src}-{dst}-{sport}-{dport}-{payload}"
                return hashlib.md5(packet_data.encode()).hexdigest()
        return None

    def compare_pcaps(self, lan_tap_file, computer_tap_file, src_ip):
        lan_packets = self.load_packets(lan_tap_file)
        computer_packets = self.load_packets(computer_tap_file)
        
        lan_packet_hashes = defaultdict(list)
        computer_packet_hashes = defaultdict(list)
        
        for packet in lan_packets:
            packet_hash = self.generate_packet_hash(packet, src_ip)
            if packet_hash:
                lan_packet_hashes[packet_hash].append(packet)
        
        for packet in computer_packets:
            packet_hash = self.generate_packet_hash(packet, src_ip)
            if packet_hash:
                computer_packet_hashes[packet_hash].append(packet)
        
        missing_hashes = set(lan_packet_hashes.keys()) - set(computer_packet_hashes.keys())
        
        print("Outgoing packets in LAN tap but not captured by computer (missing hashes):")
        for missing_hash in missing_hashes:
            print(f"Packet with hash {missing_hash} is missing in computer capture.")

        print("\nIntegrity check for matched outgoing packets:")
        matched_hashes = set(lan_packet_hashes.keys()) & set(computer_packet_hashes.keys())
        
        for match_hash in matched_hashes:
            lan_payloads = [bytes(pkt.payload) for pkt in lan_packet_hashes[match_hash]]
            computer_payloads = [bytes(pkt.payload) for pkt in computer_packet_hashes[match_hash]]
            
            if lan_payloads != computer_payloads:
                print(f"Discrepancy found in outgoing packet with hash {match_hash}")

    def verify(self):
        self.compare_pcaps(lan_tap_file=self.lan_tap, computer_tap_file=self.computer_trace, src_ip=self.source_ip)
    
if __name__ == "__main__":
    vf = VerifyNetwork()
    vf.verify()

