#!/usr/bin/env python3
"""
SDN Data Collection - Production Version
Auto-cleanup, robust error handling, reliable data collection
"""

import requests
import pandas as pd
import time
import subprocess
import os
import sys
from datetime import datetime

class RobustSDNCollector:
    def __init__(self, controller_ip="localhost", controller_port=8080):
        self.controller_ip = controller_ip
        self.controller_port = controller_port
        self.base_url = f"http://{controller_ip}:{controller_port}/wm"
        self.dataset_dir = "ml_dataset"
        os.makedirs(self.dataset_dir, exist_ok=True)
        
    def cleanup_containers(self):
        """Stop all running Mininet containers"""
        print("\n[Cleanup] Stopping old containers...")
        try:
            # Get running containers
            result = subprocess.run(
                ["docker", "ps", "-q", "--filter", "ancestor=mininet-custom"],
                capture_output=True, text=True, timeout=10
            )
            
            container_ids = result.stdout.strip().split('\n')
            container_ids = [c for c in container_ids if c]  # Remove empty strings
            
            if container_ids:
                print(f"  - Found {len(container_ids)} running containers")
                for container_id in container_ids:
                    subprocess.run(["docker", "stop", container_id], timeout=30)
                    print(f"    ✓ Stopped: {container_id}")
                
                # Wait a bit for cleanup
                time.sleep(3)
                print("  ✓ All containers stopped")
            else:
                print("  ✓ No containers to clean up")
            
            return True
        except Exception as e:
            print(f"  ! Warning: Cleanup failed: {e}")
            return False
    
    def check_floodlight(self):
        """Verify Floodlight controller is accessible"""
        print("\n[Check] Floodlight Controller...")
        try:
            response = requests.get(f"{self.base_url}/core/controller/summary/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                print(f"  ✓ Connected")
                print(f"    Switches: {data.get('# Switches', 0)}")
                print(f"    Hosts: {data.get('# hosts', 0)}")
                return True
            else:
                print(f"  ✗ HTTP {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print(f"  ✗ Cannot connect - Is Floodlight running?")
            return False
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return False
    
    def collect_flow_data(self):
        """Collect current flow statistics"""
        try:
            response = requests.get(f"{self.base_url}/core/switch/all/flow/json", timeout=5)
            if response.status_code == 200:
                flows = response.json()
                if flows:  # Check if not empty dict
                    return flows
        except:
            pass
        return None
    
    def flows_to_dataframe(self, flows):
        """Convert flow statistics to DataFrame"""
        records = []
        
        for switch_dpid, switch_flows in flows.items():
            for flow in switch_flows:
                match = flow.get('match', {})
                
                record = {
                    'timestamp': datetime.now().isoformat(),
                    'switch': switch_dpid,
                    'priority': flow.get('priority', 0),
                    'duration_sec': flow.get('durationSeconds', 0),
                    'packet_count': flow.get('packetCount', 0),
                    'byte_count': flow.get('byteCount', 0),
                    'in_port': match.get('inPort', ''),
                    'dl_src': match.get('dataLayerSource', ''),
                    'dl_dst': match.get('dataLayerDestination', ''),
                    'nw_src': match.get('networkSource', ''),
                    'nw_dst': match.get('networkDestination', ''),
                    'nw_proto': match.get('networkProtocol', ''),
                    'tp_src': match.get('transportSource', ''),
                    'tp_dst': match.get('transportDestination', ''),
                    'action': str(flow.get('actions', 'DROP'))
                }
                records.append(record)
        
        return pd.DataFrame(records)
    
    def run_network_and_collect(self, duration=30):
        """Run Mininet and collect flow data"""
        print(f"\n[Collect] Starting network (duration: {duration}s)...")
        
        # Launch Mininet in background
        process = subprocess.Popen(
            ["docker", "run", "--rm", "--privileged", "mininet-custom",
             "timeout", str(duration), "mn", 
             "--switch", "user",
             "--controller", f"remote,ip=192.168.1.7,port=6653",
             "--topo", "single,4",
             "--test", "pingall"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        print("  - Network starting...")
        time.sleep(15)  # Wait for network to initialize
        
        # Collect data periodically
        print("  - Collecting flow statistics...")
        all_data = []
        
        for round_num in range((duration - 15) // 5):  # Collect every 5 seconds
            flows = self.collect_flow_data()
            
            if flows:
                df = self.flows_to_dataframe(flows)
                if not df.empty:
                    df['round'] = round_num
                    all_data.append(df)
                    print(f"    Round {round_num + 1}: {len(df)} flows")
            else:
                print(f"    Round {round_num + 1}: No flows yet...")
            
            time.sleep(5)
        
        # Wait for Mininet to finish
        print("  - Waiting for network to complete...")
        try:
            process.wait(timeout=10)
        except:
            process.kill()
        
        # Combine collected data
        if all_data:
            combined = pd.concat(all_data, ignore_index=True)
            print(f"  ✓ Collected {len(combined)} total flow records")
            return combined
        else:
            print("  ✗ No data collected!")
            return pd.DataFrame()
    
    def analyze_dataset(self, df):
        """Show analysis of collected data"""
        if df.empty:
            return
        
        print(f"\n{'='*70}")
        print("DATASET ANALYSIS")
        print(f"{'='*70}")
        
        print(f"\n📊 Dataset Info:")
        print(f"  Records: {len(df)}")
        print(f"  Features: {len(df.columns)}")
        print(f"  Size: {df.memory_usage(deep=True).sum() / 1024:.2f} KB")
        
        print(f"\n🔀 Traffic Distribution:")
        print(f"  Unique sources: {df['nw_src'].nunique()}")
        print(f"  Unique destinations: {df['nw_dst'].nunique()}")
        print(f"  Protocols: {df['nw_proto'].value_counts().to_dict()}")
        
        print(f"\n📈 Flow Statistics:")
        print(f"  Total packets: {df['packet_count'].sum():,}")
        print(f"  Total bytes: {df['byte_count'].sum():,}")
        print(f"  Avg duration: {df['duration_sec'].mean():.2f}s")
        
        print(f"\n🔍 Sample Flows:")
        cols = ['switch', 'nw_src', 'nw_dst', 'packet_count', 'byte_count']
        print(df[cols].head(5).to_string(index=False))
    
    def run_complete_workflow(self):
        """Execute complete collection workflow"""
        print("\n" + "="*70)
        print("  SDN DATA COLLECTION - AUTO-CLEANUP VERSION")
        print("="*70)
        
        # Step 1: Cleanup
        self.cleanup_containers()
        
        # Step 2: Check Floodlight
        if not self.check_floodlight():
            print("\n❌ FAILED: Floodlight not accessible")
            print("\nPlease ensure Floodlight is running:")
            print("  cd floodlight_with_topoguard")
            print("  java -jar target\\floodlight.jar")
            return False
        
        # Step 3: Collect data
        df = self.run_network_and_collect(duration=30)
        
        if df.empty:
            print("\n❌ FAILED: No data collected")
            print("\nPossible issues:")
            print("  - Network didn't start properly")
            print("  - No traffic generated")
            print("  - Switches didn't connect to controller")
            return False
        
        # Step 4: Save dataset
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.dataset_dir}/sdn_flows_{timestamp}.csv"
        df.to_csv(filename, index=False)
        print(f"\n💾 Saved: {filename}")
        
        # Step 5: Analyze
        self.analyze_dataset(df)
        
        # Success summary
        print(f"\n{'='*70}")
        print("✅ SUCCESS!")
        print(f"{'='*70}")
        print(f"\nDataset ready: {filename}")
        print(f"Records: {len(df)}")
        print(f"\nNext steps:")
        print(f"  1. python main.py  # Run ML pipeline")
        print(f"  2. Train models on collected data")
        print(f"  3. Test attack detection")
        
        return True

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║          SDN Data Collection - Auto-Cleanup Version         ║
║                                                              ║
║  ✓ Automatically stops old containers                       ║
║  ✓ Ensures clean environment                                ║
║  ✓ Collects flow data from Floodlight                       ║
║  ✓ Creates ML-ready CSV dataset                             ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Verify Docker
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, timeout=5)
        if result.returncode != 0:
            raise Exception("Docker not working")
        print("✓ Docker available\n")
    except:
        print("❌ Docker not found or not running")
        sys.exit(1)
    
    # Run collection
    collector = RobustSDNCollector()
    success = collector.run_complete_workflow()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
