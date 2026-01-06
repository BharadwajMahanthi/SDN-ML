#!/usr/bin/env python3
"""
Complete SDN Data Collection - Using Floodlight REST API
Reliable data collection from controller instead of packet capture
"""

import requests
import pandas as pd
import time
import subprocess
import os
import sys
from datetime import datetime
import json

class FloodlightDataCollector:
    def __init__(self, controller_ip="localhost", controller_port=8080):
        self.controller_ip = controller_ip
        self.controller_port = controller_port
        self.base_url = f"http://{controller_ip}:{controller_port}/wm"
        self.dataset_dir = "ml_dataset"
        os.makedirs(self.dataset_dir, exist_ok=True)
        
    def check_controller(self):
        """Check if Floodlight is running"""
        print("\n[*] Checking Floodlight Controller...")
        try:
            response = requests.get(f"{self.base_url}/core/controller/summary/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                print(f"  ✓ Controller is running")
                print(f"    Switches: {data.get('# Switches', 0)}")
                print(f"    Hosts: {data.get('# hosts', 0)}")
                return True
        except:
            print(f"  ✗ Cannot connect to controller")
            return False
        return False
    
    def get_flow_stats(self):
        """Get flow statistics from all switches"""
        try:
            response = requests.get(f"{self.base_url}/core/switch/all/flow/json", timeout=5)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return {}
    
    def get_port_stats(self):
        """Get port statistics"""
        try:
            response = requests.get(f"{self.base_url}/statistics/port/all/json", timeout=5)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return {}
    
    def parse_flows_to_dataframe(self, flows):
        """Convert flow data to pandas DataFrame"""
        records = []
        
        for switch_dpid, switch_flows in flows.items():
            for flow in switch_flows:
                record = {
                    'timestamp': datetime.now().isoformat(),
                    'switch_dpid': switch_dpid,
                    'priority': flow.get('priority', 0),
                    'duration_sec': flow.get('durationSeconds', 0),
                    'idle_timeout': flow.get('idleTimeout', 0),
                    'hard_timeout': flow.get('hardTimeout', 0),
                    'packet_count': flow.get('packetCount', 0),
                    'byte_count': flow.get('byteCount', 0),
                    'table_id': flow.get('tableId', 0),
                }
                
                # Extract match fields
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
                
                # Actions
                actions = flow.get('actions', [])
                record['action'] = str(actions) if actions else 'DROP'
                
                records.append(record)
        
        return pd.DataFrame(records)
    
    def run_mininet_scenario(self, scenario="normal", test_duration=30):
        """Run Mininet network and collect data"""
        print(f"\n[*] Running Mininet scenario: {scenario}")
        print(f"    Duration: {test_duration} seconds")
        
        docker_cmd = [
            "docker", "run", "--rm", "--privileged",
            "mininet-custom",
            "bash", "-c",
            f"timeout {test_duration} mn --switch user --controller=remote,ip=192.168.1.7,port=6653 --topo single,4 --test pingall"
        ]
        
        try:
            #Start Mininet in background
            print("  - Starting Mininet network...")
            process = subprocess.Popen(docker_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait a bit for network to start
            time.sleep(10)
            
            # Collect flow data periodically
            print("  - Collecting flow statistics...")
            all_data = []
            
            for i in range(test_duration // 5):  # Collect every 5 seconds
                flows = self.get_flow_stats()
                if flows:
                    df = self.parse_flows_to_dataframe(flows)
                    if not df.empty:
                        df['collection_round'] = i
                        all_data.append(df)
                        print(f"    Round {i+1}: Collected {len(df)} flow entries")
                time.sleep(5)
            
            # Wait for Mininet to finish
            process.wait(timeout=test_duration+10)
            
            # Combine all data
            if all_data:
                combined_df = pd.concat(all_data, ignore_index=True)
                print(f"  ✓ Total collected: {len(combined_df)} flow records")
                return combined_df
            else:
                print("  ✗ No flow data collected")
                return pd.DataFrame()
                
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return pd.DataFrame()
    
    def analyze_data(self, df, scenario):
        """Analyze collected data"""
        if df.empty:
            print(f"\n✗ No data to analyze for {scenario}")
            return
        
        print(f"\n{'='*60}")
        print(f"DATA ANALYSIS: {scenario}")
        print(f"{'='*60}")
        
        print(f"\nDataset Shape: {df.shape}")
        print(f"  - {len(df)} flow records")
        print(f"  - {len(df.columns)} features")
        
        print(f"\nSwitch Distribution:")
        print(df['switch_dpid'].value_counts())
        
        print(f"\nProtocol Distribution:")  
        print(df['nw_proto'].value_counts().head())
        
        print(f"\nTraffic Statistics:")
        print(f"  - Total packets: {df['packet_count'].sum():,}")
        print(f"  - Total bytes: {df['byte_count'].sum():,}")
        print(f"  - Avg packets/flow: {df['packet_count'].mean():.2f}")
        print(f"  - Avg bytes/flow: {df['byte_count'].mean():.2f}")
        
        print(f"\nUnique Sources: {df['nw_src'].nunique()}")
        print(f"Unique Destinations: {df['nw_dst'].nunique()}")
        
        print(f"\nSample Data:")
        print(df[['switch_dpid', 'nw_src', 'nw_dst', 'packet_count', 'byte_count']].head(10))
    
    def run_complete_collection(self):
        """Run complete data collection workflow"""
        print("\n" + "="*70)
        print(" "*15 + "SDN DATA COLLECTION AUTOMATION")
        print("="*70)
        
        # Check controller
        if not self.check_controller():
            print("\n✗ Floodlight is not running!")
            print("\nPlease start Floodlight first:")
            print("  1. Open new terminal")
            print("  2. cd floodlight_with_topoguard")
            print("  3. java -jar target\\floodlight.jar")
            return False
        print("\n✓ Floodlight is ready\n")
        
        # Define scenarios
        scenarios = [
            ("normal_traffic", 30, "Normal network baseline"),
        ]
        
        all_datasets = {}
        
        for scenario_name, duration, description in scenarios:
            print(f"\n{'='*70}")
            print(f"SCENARIO: {description}")
            print(f"{'='*70}")
            
            # Run scenario and collect data
            df = self.run_mininet_scenario(scenario_name, duration)
            
            if not df.empty:
                # Add scenario label
                df['scenario'] = scenario_name
                df['label'] = 'normal'  # Change to 'attack' for attack scenarios
                
                # Save to CSV
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{self.dataset_dir}/{scenario_name}_{timestamp}.csv"
                df.to_csv(filename, index=False)
                print(f"  ✓ Saved to: {filename}")
                
                # Analyze
                self.analyze_data(df, scenario_name)
                
                all_datasets[scenario_name] = df
            
            print(f"\nWaiting 10 seconds before next scenario...")
            time.sleep(10)
        
        # Final summary
        print(f"\n{'='*70}")
        print("COLLECTION COMPLETE!")
        print(f"{'='*70}")
        
        if all_datasets:
            print(f"\n✓ Collected {len(all_datasets)} scenarios:")
            for name, df in all_datasets.items():
                print(f"    - {name}: {len(df)} records")
            
            print(f"\nDataset saved in: {self.dataset_dir}/")
            print("\nNext steps:")
            print("  1. Review data: ls ml_dataset/")
            print("  2. Run ML pipeline: python main.py")
            print("  3. Train attack detection models")
            
            return True
        else:
            print("\n✗ No data was collected")
            return False

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║         SDN Attack Detection - Data Collection              ║
║                                                              ║
║  Collects flow statistics from Floodlight controller        ║
║  during Mininet network operation for ML analysis           ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Check Docker
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, timeout=5)
        if result.returncode != 0:
            print("✗ Docker is not available")
            sys.exit(1)
        print("✓ Docker is available")
    except:
        print("✗ Docker is not installed")
        sys.exit(1)
    
    # Run collection
    collector = FloodlightDataCollector()
    success = collector.run_complete_collection()
    
    if success:
        print("\n✓ SUCCESS! Data collection completed.")
    else:
        print("\n✗ FAILED. Please check errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
