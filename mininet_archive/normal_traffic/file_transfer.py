#!/usr/bin/env python3
"""
Normal File Transfer Traffic (FTP/Large Data)
Simulates legitimate file transfers and data movement
"""

import time
import random
from scapy.all import *

def generate_ftp_session(src_ip, dst_ip, file_size_mb=10):
    """
    Simulate FTP file transfer
    
    Args:
        src_ip: Source host IP
        dst_ip: Destination host IP
        file_size_mb: Simulated file size in MB
    """
    print(f"[*] Simulating FTP transfer: {src_ip} -> {dst_ip}")
    print(f"[*] File size: {file_size_mb} MB")
    
    # FTP control connection (port 21)
    ftp_control = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=21, flags='PA')
    send(ftp_control, verbose=False)
    
    # FTP data connection (port 20)
    # Simulate data transfer with packets
    packet_count = file_size_mb * 100  # Roughly 100 packets per MB
    
    for i in range(packet_count):
        data_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=20, flags='PA') / Raw(load='X'*1400)
        send(data_pkt, verbose=False)
        
        if (i+1) % 100 == 0:
            progress = (i+1) / packet_count * 100
            print(f"[+] Transfer progress: {progress:.1f}%")
        
        time.sleep(0.01)  # Simulate realistic transfer rate
    
    print(f"[✓] Transfer completed: {file_size_mb} MB")

def simulate_data_transfers(host_pairs, transfers=5, file_sizes=[5, 10, 20]):
    """
    Simulate multiple file transfers
    
    Args:
        host_pairs: List of (src, dst) tuples
        transfers: Number of transfers to simulate
        file_sizes: Possible file sizes in MB
    """
    print(f"[*] Simulating {transfers} file transfers")
    
    for i in range(transfers):
        src, dst = random.choice(host_pairs)
        size = random.choice(file_sizes)
        
        print(f"\n[*] Transfer {i+1}/{transfers}")
        generate_ftp_session(src, dst, size)
        
        # Pause between transfers
        time.sleep(2)
    
    print("\n[✓] All transfers completed")

if __name__ == "__main__":
    # Define server-client pairs
    host_pairs = [
        ("10.0.0.1", "10.0.0.6"),  # Client to Storage Server
        ("10.0.0.2", "10.0.0.6"),
        ("10.0.0.3", "10.0.0.6"),
        ("10.0.0.4", "10.0.0.6"),
    ]
    
    try:
        simulate_data_transfers(host_pairs, transfers=3, file_sizes=[5, 10])
    except PermissionError:
        print("[!] Error: Requires root/administrator privileges")
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
    except Exception as e:
        print(f"[!] Error: {e}")
