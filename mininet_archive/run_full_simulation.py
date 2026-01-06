#!/usr/bin/env python3
"""
FINAL Production SDN Data Collection
- Auto-cleanup
- Sustained traffic generation 
- Reliable flow collection from Floodlight
- ML-ready CSV output
"""

import requests
import pandas as pd
import time
import subprocess
import os
import sys
from datetime import datetime
import threading

class ProductionSDNCollector:
    def __init__(self):
        self.controller_ip = "localhost"
        self.controller_port = 8080
        self.base_url = f"http://{self.controller_ip}:{self.controller_port}/wm"
        self.dataset_dir = "ml_dataset"
        os.makedirs(self.dataset_dir, exist_ok=True)
        self.collecting = False
        
    def cleanup(self):
        """Stop old containers"""
        print("\n[Step 1/5] Cleanup...")
        try:
            result = subprocess.run(
                ["docker", "ps", "-q", "--filter", "ancestor=mininet-custom"],
                capture_output=True, text=True, timeout=10
            )
            containers = [c for c in result.stdout.strip().split('\n') if c]
            
            if containers:
                for cid in containers:
                    subprocess.run(["docker", "stop", cid], timeout=30, capture_output=True)
                print(f"  ✓ Stopped {len(containers)} old containers")
            else:
                print("  ✓ No cleanup needed")
            return True
        except Exception as e:
            print(f"  ! Warning: {e}")
            return False
    
    def check_controller(self):
        """Verify Floodlight"""
        print("\n[Step 2/5] Checking Floodlight...")
        try:
            r = requests.get(f"{self.base_url}/core/controller/summary/json", timeout=5)
            if r.status_code == 200:
                print("  ✓ Controller ready")
                return True
        except:
            pass
        print("  ✗ Floodlight not accessible!")
        return False
    
    def get_flows(self):
        """Get current flows"""
        try:
            r = requests.get(f"{self.base_url}/core/switch/all/flow/json", timeout=3)
            if r.status_code == 200:
                return r.json()
        except:
            pass
        return {}
    
    def flows_to_df(self, flows):
        """Convert to DataFrame"""
        records = []
        for sw, flows_list in flows.items():
            for f in flows_list:
                m = f.get('match', {})
                records.append({
                    'time': datetime.now().isoformat(),
                    'switch': sw,
                    'priority': f.get('priority', 0),
                    'duration': f.get('durationSeconds', 0),
                    'packets': f.get('packetCount', 0),
                    'bytes': f.get('byteCount', 0),
                    'src_ip': m.get('networkSource', ''),
                    'dst_ip': m.get('networkDestination', ''),
                    'protocol': m.get('networkProtocol', ''),
                    'src_port': m.get('transportSource', ''),
                    'dst_port': m.get('transportDestination', ''),
                })
        return pd.DataFrame(records)
    
    def collect_data_thread(self, duration, data_list):
        """Background thread to collect data"""
        self.collecting = True
        end_time = time.time() + duration
        round_num = 0
        
        while time.time() < end_time and self.collecting:
            flows = self.get_flows()
            if flows:
                df = self.flows_to_df(flows)
                if not df.empty:
                    df['round'] = round_num
                    data_list.append(df)
                    print(f"    • Round {round_num + 1}: {len(df)} flows")
                    round_num += 1
            time.sleep(3)  # Collect every 3 seconds
    
    def run_simulation(self, duration=45):
        """Run complete simulation"""
        print(f"\n[Step 3/5] Starting {duration}s simulation...")
        
        # Start Mininet with ping traffic
        print("  - Launching network...")
        mininet_script = f"""
mn --switch user --controller=remote,ip=192.168.1.7,port=6653 --topo single,4 << 'EOF'
pingall
h1 ping -c 50 -i 0.5 h4 &
h2 ping -c 50 -i 0.5 h3 &
sleep {duration}
exit
EOF
"""
        
        process = subprocess.Popen(
            ["docker", "run", "--rm", "--privileged", "mininet-custom", "bash", "-c", mininet_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for network to start
        time.sleep(15)
        print("  - Network active, collecting data...")
        
        # Start data collection in background
        collected_data = []
        collector_thread = threading.Thread(
            target=self.collect_data_thread,
            args=(duration - 15, collected_data)
        )
        collector_thread.start()
        
        # Wait for collection to complete
        collector_thread.join()
        
        # Stop Mininet
        try:
            process.terminate()
            process.wait(timeout=10)
        except:
            process.kill()
        
        print(f"  ✓ Simulation complete")
        
        # Combine data
        if collected_data:
            df = pd.concat(collected_data, ignore_index=True)
            print(f"  ✓ Collected {len(df)} total flow records")
            return df
        else:
            print("  ✗ No data collected")
            return pd.DataFrame()
    
    def analyze(self, df):
        """Analyze dataset"""
        print(f"\n[Step 4/5] Analysis...")
        
        if df.empty:
            print("  ✗ No data to analyze")
            return
        
        print(f"\n  📊 Dataset: {len(df)} records, {len(df.columns)} features")
        print(f"  🔀 Traffic: {df['src_ip'].nunique()} sources → {df['dst_ip'].nunique()} destinations")
        print(f"  📈 Totals: {df['packets'].sum():,} packets, {df['bytes'].sum():,} bytes")
        print(f"\n  Top 5 Flows:")
        print(df.nlargest(5, 'packets')[['src_ip', 'dst_ip', 'packets', 'bytes']].to_string(index=False))
    
    def save(self, df):
        """Save dataset"""
        print(f"\n[Step 5/5] Saving...")
        
        if df.empty:
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.dataset_dir}/sdn_baseline_{timestamp}.csv"
        df.to_csv(filename, index=False)
        
        print(f"  ✓ Saved: {filename}")
        print(f"  ✓ Size: {os.path.getsize(filename) / 1024:.2f} KB")
        
        return filename
    
    def run(self):
        """Execute complete workflow"""
        print("\n" + "="*70)
        print("  COMPLETE SDN DATA COLLECTION SIMULATION")
        print("="*70)
        
        # Execute steps
        if not self.cleanup():
            return False
        
        if not self.check_controller():
            print("\n❌ FAILED: Start Floodlight first!")
            return False
        
        df = self.run_simulation(duration=45)
        
        if df.empty:
            print("\n❌ FAILED: No data collected")
            print("\nTroubleshooting:")
            print("  1. Check if switches connected: curl http://localhost:8080/wm/core/controller/switches/json")
            print("  2. Verify network started properly")
            print("  3. Check Floodlight logs")
            return False
        
        self.analyze(df)
        filename = self.save(df)
        
        # Success!
        print(f"\n" + "="*70)
        print("✅ SUCCESS!")
        print("="*70)
        print(f"\n📁 Dataset: {filename}")
        print(f"📊 Records: {len(df)}")
        print(f"\n🎓 Next Steps:")
        print(f"  1. Explore data: pd.read_csv('{filename}')")
        print(f"  2. Run ML pipeline: python main.py")
        print(f"  3. Train attack detection models")
        
        return True

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║              SDN DATA COLLECTION - FULL SIMULATION          ║
║                                                              ║
║  This will run a complete 45-second network simulation      ║
║  with traffic generation and flow data collection           ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    collector = ProductionSDNCollector()
    success = collector.run()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
