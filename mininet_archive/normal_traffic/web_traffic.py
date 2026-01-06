#!/usr/bin/env python3
"""
Normal HTTP Web Traffic Generator
Simulates legitimate web browsing traffic between hosts
"""

import time
import random
from scapy.all import *

def generate_http_request(src_ip, dst_ip, dst_port=80):
    """Generate a realistic HTTP GET request"""
    
    # Simulate TCP handshake
    syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags='S')
    
    # HTTP GET request
    http_payload = f"GET / HTTP/1.1\r\nHost: {dst_ip}\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n"
    
    http_req = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags='PA') / Raw(load=http_payload)
    
    return [syn, http_req]

def simulate_web_traffic(hosts, duration=60, requests_per_minute=10):
    """
    Simulate normal web browsing between hosts
    
    Args:
        hosts: List of (src_ip, dst_ip) tuples
        duration: How long to generate traffic (seconds)
        requests_per_minute: Rate of requests
    """
    print(f"[*] Simulating normal web traffic")
    print(f"[*] Duration: {duration} seconds")
    print(f"[*] Rate: {requests_per_minute} requests/minute")
    print(f"[*] Hosts: {len(hosts)} pairs")
    
    start_time = time.time()
    request_count = 0
    
    while (time.time() - start_time) < duration:
        # Pick random host pair
        src, dst = random.choice(hosts)
        
        # Generate HTTP traffic
        packets = generate_http_request(src, dst)
        
        for pkt in packets:
            send(pkt, verbose=False)
        
        request_count += 1
        
        if request_count % 10 == 0:
            print(f"[+] Generated {request_count} web requests")
        
        # Sleep to maintain rate
        sleep_time = 60.0 / requests_per_minute
        time.sleep(sleep_time)
    
    print(f"[✓] Completed: {request_count} total requests")

if __name__ == "__main__":
    # Define host pairs for communication
    host_pairs = [
        ("10.0.0.1", "10.0.0.2"),
        ("10.0.0.1", "10.0.0.4"),
        ("10.0.0.2", "10.0.0.3"),
        ("10.0.0.3", "10.0.0.4"),
        ("10.0.0.5", "10.0.0.6"),
    ]
    
    try:
        simulate_web_traffic(host_pairs, duration=120, requests_per_minute=20)
    except PermissionError:
        print("[!] Error: Requires root/administrator privileges")
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
    except Exception as e:
        print(f"[!] Error: {e}")
