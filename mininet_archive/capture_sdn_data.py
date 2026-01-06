#!/usr/bin/env python3
"""
SDN Flow Data Collector
Captures flow statistics from Floodlight controller for ML analysis
"""

import requests
import json
import csv
import time
from datetime import datetime

class FloodlightDataCollector:
    def __init__(self, controller_ip="192.168.1.16", controller_port=8080):
        self.base_url = f"http://{controller_ip}:{controller_port}/wm"
        self.flows_url = f"{self.base_url}/core/switch/all/flow/json"
        self.stats_url = f"{self.base_url}/statistics/port/all/json"
        self.topology_url = f"{self.base_url}/topology/links/json"
        
    def get_flows(self):
        """Fetch current flow entries from all switches"""
        try:
            response = requests.get(self.flows_url, timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"[!] Error fetching flows: HTTP {response.status_code}")
                return {}
        except Exception as e:
            print(f"[!] Error connecting to controller: {e}")
            return {}
    
    def get_port_stats(self):
        """Fetch port statistics"""
        try:
            response = requests.get(self.stats_url, timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                return {}
        except Exception as e:
            print(f"[!] Error fetching port stats: {e}")
            return {}
    
    def parse_flow_data(self, flows):
        """Parse flow entries into structured data"""
        flow_records = []
        
        for switch_dpid, switch_flows in flows.items():
            for flow in switch_flows:
                # Extract relevant fields
                record = {
                    'timestamp': datetime.now().isoformat(),
                    'switch': switch_dpid,
                    'priority': flow.get('priority', 0),
                    'duration_sec': flow.get('durationSeconds', 0),
                    'idle_timeout': flow.get('idleTimeout', 0),
                    'hard_timeout': flow.get('hardTimeout', 0),
                    'packet_count': flow.get('packetCount', 0),
                    'byte_count': flow.get('byteCount', 0),
                    'table_id': flow.get('tableId', 0),
                }
                
                # Parse match fields
                match = flow.get('match', {})
                record['in_port'] = match.get('inPort', '')
                record['dl_src'] = match.get('dataLayerSource', '')
                record['dl_dst'] = match.get('dataLayerDestination', '')
                record['dl_type'] = match.get('dataLayerType', '')
                record['nw_src'] = match.get('networkSource', '')
                record['nw_dst'] = match.get('networkDestination', '')
                record['nw_proto'] = match.get('networkProtocol', '')
                record['tp_src'] = match.get('transportSource', '')
                record['tp_dst'] = match.get('transportDestination', '')
                
                # Parse actions
                actions = flow.get('actions', [])
                record['action'] = ','.join([str(a) for a in actions]) if actions else 'DROP'
                
                flow_records.append(record)
        
        return flow_records
    
    def save_to_csv(self, records, filename='sdn_flow_data.csv'):
        """Save flow records to CSV file"""
        if not records:
            print("[!] No records to save")
            return
        
        # Define CSV headers
        headers = [
            'timestamp', 'switch', 'priority', 'duration_sec', 
            'idle_timeout', 'hard_timeout', 'packet_count', 'byte_count',
            'table_id', 'in_port', 'dl_src', 'dl_dst', 'dl_type',
            'nw_src', 'nw_dst', 'nw_proto', 'tp_src', 'tp_dst', 'action'
        ]
        
        # Check if file exists to determine if we need to write headers
        try:
            with open(filename, 'r'):
                write_header = False
        except FileNotFoundError:
            write_header = True
        
        # Write to CSV
        with open(filename, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            
            if write_header:
                writer.writeheader()
            
            writer.writerows(records)
        
        print(f"[+] Saved {len(records)} flow records to {filename}")
    
    def collect_continuously(self, interval=10, duration=300, output_file='sdn_flow_data.csv'):
        """
        Continuously collect flow data
        
        Args:
            interval: Collection interval in seconds
            duration: Total collection duration in seconds
            output_file: Output CSV filename
        """
        print(f"[*] Starting continuous data collection")
        print(f"[*] Interval: {interval} seconds")
        print(f"[*] Duration: {duration} seconds")
        print(f"[*] Output: {output_file}")
        
        start_time = time.time()
        collection_count = 0
        
        while (time.time() - start_time) < duration:
            # Fetch flows
            flows = self.get_flows()
            
            if flows:
                # Parse and save
                records = self.parse_flow_data(flows)
                self.save_to_csv(records, output_file)
                
                collection_count += 1
                print(f"[+] Collection #{collection_count}: {len(records)} flows captured")
            else:
                print(f"[!] No flows retrieved at collection #{collection_count + 1}")
            
            # Wait for next interval
            time.sleep(interval)
        
        print(f"\n[✓] Data collection completed: {collection_count} collections")
        print(f"[✓] Data saved to: {output_file}")

def main():
    print("=== SDN Flow Data Collector ===\n")
    
    # Initialize collector
    collector = FloodlightDataCollector(
        controller_ip="192.168.1.16",  # Update to your controller IP
        controller_port=8080
    )
    
    # Test connection
    print("[*] Testing connection to Floodlight...")
    test_flows = collector.get_flows()
    
    if test_flows:
        print(f"[✓] Connected! Found {len(test_flows)} switches")
    else:
        print("[!] Unable to connect to Floodlight controller")
        print("[!] Make sure:")
        print("    1. Floodlight is running")
        print("    2. Controller IP is correct (192.168.1.16:8080)")
        print("    3. Firewall allows connection")
        return
    
    # Start continuous collection
    try:
        collector.collect_continuously(
            interval=10,      # Collect every 10 seconds
            duration=300,     # Run for 5 minutes
            output_file='sdn_attack_dataset.csv'
        )
    except KeyboardInterrupt:
        print("\n[!] Collection stopped by user")
    except Exception as e:
        print(f"\n[!] Error during collection: {e}")

if __name__ == "__main__":
    main()
