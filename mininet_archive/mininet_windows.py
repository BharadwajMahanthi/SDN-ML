"""
Simple Python-based SDN Network Emulator for Windows
Emulates basic Mininet functionality using Python networking
"""

import socket
import threading
import time
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler

class SimpleSwitch:
    """Emulates an OpenFlow switch"""
    def __init__(self, dpid, controller_ip='127.0.0.1', controller_port=6653):
        self.dpid = dpid
        self.controller_ip = controller_ip
        self.controller_port = controller_port
        self.hosts = []
        self.running = False
        
    def add_host(self, host):
        """Add a host to this switch"""
        self.hosts.append(host)
        
    def connect_to_controller(self):
        """Connect to OpenFlow controller (Floodlight)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.controller_ip, self.controller_port))
            print(f"[Switch {self.dpid}] Connected to controller at {self.controller_ip}:{self.controller_port}")
            
            # Send simple OpenFlow HELLO message
            # This is a simplified version - real OpenFlow is more complex
            hello_msg = b'\x04\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00'
            sock.send(hello_msg)
            
            self.running = True
            while self.running:
                time.sleep(1)
                
        except Exception as e:
            print(f"[Switch {self.dpid}] Connection error: {e}")
        finally:
            sock.close()

class SimpleHost:
    """Emulates a network host"""
    def __init__(self, name, ip, port=8000):
        self.name = name
        self.ip = ip
        self.port = port
        self.server = None
        
    def start_server(self):
        """Start a simple HTTP server on this host"""
        class HostHandler(BaseHTTPRequestHandler):
            host_name = self.name
            
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                response = f"<html><body><h1>Host {self.host_name}</h1><p>IP: {self.server.server_address}</p></body></html>"
                self.wfile.write(response.encode())
                
            def log_message(self, format, *args):
                print(f"[{self.host_name}] {format % args}")
        
        try:
            self.server = HTTPServer((self.ip, self.port), HostHandler)
            print(f"[{self.name}] HTTP server started on {self.ip}:{self.port}")
            self.server.serve_forever()
        except Exception as e:
            print(f"[{self.name}] Server error: {e}")
    
    def ping(self, target_ip, target_port=8000):
        """Simulate ping to another host"""
        try:
            response = requests.get(f"http://{target_ip}:{target_port}", timeout=2)
            if response.status_code == 200:
                print(f"[{self.name}] Ping to {target_ip} successful!")
                return True
        except Exception as e:
            print(f"[{self.name}] Ping to {target_ip} failed: {e}")
        return False

class SimpleTopology:
    """Emulates a simple network topology"""
    def __init__(self):
        self.switches = []
        self.hosts = []
        self.threads = []
        
    def add_switch(self, dpid):
        """Add a switch to the topology"""
        switch = SimpleSwitch(dpid)
        self.switches.append(switch)
        return switch
        
    def add_host(self, name, ip, switch):
        """Add a host connected to a switch"""
        host = SimpleHost(name, ip)
        self.hosts.append(host)
        switch.add_host(host)
        return host
        
    def start(self):
        """Start the topology"""
        print("\n=== Starting Network Topology ===\n")
        
        # Start switches in background
        for switch in self.switches:
            t = threading.Thread(target=switch.connect_to_controller, daemon=True)
            t.start()
            self.threads.append(t)
            time.sleep(0.5)
        
        # Start hosts in background
        for host in self.hosts:
            t = threading.Thread(target=host.start_server, daemon=True)
            t.start()
            self.threads.append(t)
            time.sleep(0.5)
        
        print("\n=== Topology Running ===")
        print("Available commands:")
        print("  pingall  - Test connectivity between all hosts")
        print("  info     - Show topology information")
        print("  exit     - Stop the topology")
        print()
        
    def pingall(self):
        """Test connectivity between all hosts"""
        print("\n*** Testing connectivity ***")
        for host in self.hosts:
            for target in self.hosts:
                if host != target:
                    result = "✓" if host.ping(target.ip, target.port) else "✗"
                    print(f"{host.name} -> {target.name}: {result}")
        print()
        
    def info(self):
        """Show topology information"""
        print("\n*** Topology Info ***")
        print(f"Switches: {len(self.switches)}")
        for switch in self.switches:
            print(f"  s{switch.dpid}: {len(switch.hosts)} hosts")
        print(f"Hosts: {len(self.hosts)}")
        for host in self.hosts:
            print(f"  {host.name}: {host.ip}:{host.port}")
        print()

def create_tree_topology(depth=2, fanout=2):
    """Create a tree topology similar to Mininet"""
    topo = SimpleTopology()
    
    # Create switches
    s1 = topo.add_switch(1)
    s2 = topo.add_switch(2)
    s3 = topo.add_switch(3)
    
    # Create hosts
    h1 = topo.add_host("h1", "127.0.0.1", 8001)
    h2 = topo.add_host("h2", "127.0.0.1", 8002)
    h3 = topo.add_host("h3", "127.0.0.1", 8003)
    h4 = topo.add_host("h4", "127.0.0.1", 8004)
    
    return topo

if __name__ == "__main__":
    print("=== Windows-Native SDN Network Emulator ===")
    print("Emulates Mininet functionality using Python\n")
    
    # Create topology
    topo = create_tree_topology()
    topo.start()
    
    # Interactive CLI
    try:
        while True:
            cmd = input("mininet> ").strip().lower()
            
            if cmd == "pingall":
                topo.pingall()
            elif cmd == "info":
                topo.info()
            elif cmd == "exit":
                print("Stopping topology...")
                break
            elif cmd == "help":
                print("Commands: pingall, info, exit, help")
            else:
                print(f"Unknown command: {cmd}")
                
    except KeyboardInterrupt:
        print("\nStopping topology...")
    
    print("Done.")
