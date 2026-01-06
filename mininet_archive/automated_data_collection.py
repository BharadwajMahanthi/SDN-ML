#!/usr/bin/env python3
"""
Complete SDN Data Collection Automation
Handles Floodlight status check, Mininet launch, packet capture, and ML dataset creation
"""

import subprocess
import time
import requests
import pandas as pd
import os
import sys
from datetime import datetime

class SDNDataCollector:
    def __init__(self, controller_ip="192.168.1.7", controller_port=8080):
        self.controller_ip = controller_ip
        self.controller_port = controller_port
        self.base_url = f"http://{controller_ip}:{controller_port}/wm"
        self.capture_dir = "captured_traffic"
        self.dataset_dir = "ml_dataset"
        
        # Create directories
        os.makedirs(self.capture_dir, exist_ok=True)
        os.makedirs(self.dataset_dir, exist_ok=True)
    
    def check_floodlight(self):
        """Check if Floodlight controller is running"""
        print("\n[Step 1] Checking Floodlight Controller...")
        try:
            response = requests.get(f"{self.base_url}/core/controller/summary/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                print(f"  ✓ Floodlight is running")
                print(f"    - Switches: {data.get('# Switches', 0)}")
                print(f"    - Hosts: {data.get('# hosts', 0)}")
                return True
            else:
                print(f"  ✗ Floodlight returned HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"  ✗ Cannot connect to Floodlight: {e}")
            print("\n  Please start Floodlight first:")
            print("    cd floodlight_with_topoguard")
            print("    java -jar target\\floodlight.jar")
            return False
    
    def run_mininet_with_capture(self, scenario="normal", duration=60):
        """
        Run Mininet network with packet capture
        
        Args:
            scenario: "normal", "attack_hijack", "attack_lldp", or "attack_ddos"
            duration: Capture duration in seconds
        """
        print(f"\n[Step 2] Running Mininet with {scenario} scenario ({duration}s)...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = f"{self.capture_dir}/{scenario}_{timestamp}.pcap"
        csv_file = f"{self.dataset_dir}/{scenario}_{timestamp}.csv"
        
        # Docker command to run Mininet with tcpdump
        docker_cmd = [
            "docker", "run", "--rm", "--privileged",
            "-v", f"{os.getcwd()}:/workspace",
            "mininet-custom",
            "bash", "-c", f"""
                # Start tcpdump in background
                tcpdump -i any -w /workspace/{pcap_file} -U &
                TCPDUMP_PID=$!
                
                # Start Mininet
                timeout {duration} mn --switch user --controller=remote,ip={self.controller_ip},port=6653 --topo single,4 --test pingall
                
                # Stop tcpdump
                kill $TCPDUMP_PID 2>/dev/null
                wait $TCPDUMP_PID 2>/dev/null
                
                # Convert PCAP to CSV
                tshark -r /workspace/{pcap_file} -T fields \
                    -e frame.time_epoch -e ip.src -e ip.dst -e ip.proto \
                    -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
                    -e frame.len -e ip.ttl -e tcp.flags -e arp.opcode \
                    -E header=y -E separator=, -E quote=d -E occurrence=f \
                    > /workspace/{csv_file} 2>/dev/null || echo "No packets captured"
                
                echo "Captured to: {pcap_file}"
                echo "CSV created: {csv_file}"
            """
        ]
        
        try:
            print(f"  - Launching Mininet...")
            print(f"  - Capturing to: {pcap_file}")
            
            result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=duration+30)
            
            if result.returncode == 0:
                print(f"  ✓ Capture complete")
                print(f"  ✓ PCAP: {pcap_file}")
                print(f"  ✓ CSV: {csv_file}")
                return pcap_file, csv_file
            else:
                print(f"  ✗ Mininet failed: {result.stderr}")
                return None, None
                
        except subprocess.TimeoutExpired:
            print(f"  ! Timeout after {duration+30}s")
            return pcap_file, csv_file
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return None, None
    
    def analyze_captured_data(self, csv_file):
        """Analyze captured packet data"""
        print(f"\n[Step 3] Analyzing captured data: {csv_file}")
        
        if not os.path.exists(csv_file):
            print(f"  ✗ File not found: {csv_file}")
            return None
        
        if os.path.getsize(csv_file) == 0:
            print(f"  ✗ File is empty")
            return None
        
        try:
            # Load data
            df = pd.read_csv(csv_file)
            
            print(f"  ✓ Loaded {len(df)} packets")
            print(f"\n  Data Summary:")
            print(f"    - Time range: {df['frame.time_epoch'].min():.2f} to {df['frame.time_epoch'].max():.2f}")
            print(f"    - Unique source IPs: {df['ip.src'].nunique()}")
            print(f"    - Unique dest IPs: {df['ip.dst'].nunique()}")
            print(f"    - Protocols: {df['ip.proto'].value_counts().to_dict()}")
            print(f"    - Avg packet size: {df['frame.len'].mean():.2f} bytes")
            print(f"    - Total traffic: {df['frame.len'].sum() / 1024:.2f} KB")
            
            # Show sample
            print(f"\n  Sample data (first 5 packets):")
            print(df.head().to_string())
            
            return df
            
        except Exception as e:
            print(f"  ✗ Error analyzing data: {e}")
            return None
    
    def collect_all_scenarios(self):
        """Collect data for all scenarios"""
        print("\n" + "="*60)
        print("SDN AUTOMATED DATA COLLECTION")
        print("="*60)
        
        # Check Floodlight
        if not self.check_floodlight():
            return False
        
        scenarios = [
            ("normal", 60, "Normal network traffic"),
            # Uncomment when ready for attack scenarios:
            # ("attack_hijack", 30, "Host location hijacking attack"),
            # ("attack_lldp", 30, "Link fabrication attack"),
            # ("attack_ddos", 30, "DDoS attack on controller"),
        ]
        
        captured_files = []
        
        for scenario, duration, description in scenarios:
            print(f"\n{'='*60}")
            print(f"SCENARIO: {description}")
            print(f"{'='*60}")
            
            pcap, csv = self.run_mininet_with_capture(scenario, duration)
           
            if csv and os.path.exists(csv):
                df = self.analyze_captured_data(csv)
                if df is not None:
                    captured_files.append((scenario, csv, df))
            
            print(f"\nWaiting 10 seconds before next scenario...")
            time.sleep(10)
        
        # Summary
        print(f"\n{'='*60}")
        print("COLLECTION COMPLETE")
        print(f"{'='*60}")
        print(f"\nCaptured {len(captured_files)} scenarios:")
        for scenario, csv_file, df in captured_files:
            print(f"  - {scenario}: {len(df)} packets ({csv_file})")
        
        print(f"\nFiles saved in:")
        print(f"  - PCAPs: {self.capture_dir}/")
        print(f"  - CSVs: {self.dataset_dir}/")
        
        return True

def main():
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║     SDN Attack Detection - Automated Data Collection    ║
    ║                                                          ║
    ║  This script will:                                       ║
    ║  1. Check Floodlight controller status                  ║
    ║  2. Launch Mininet network in Docker                    ║
    ║  3. Capture network traffic with tcpdump                ║
    ║  4. Convert PCAP to CSV for ML analysis                 ║
    ║  5. Analyze and summarize captured data                 ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    # Check Docker
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, timeout=5)
        if result.returncode != 0:
            print("✗ Docker is not available")
            sys.exit(1)
    except:
        print("✗ Docker is not installed or not in PATH")
        sys.exit(1)
    
    # Run collection
    collector = SDNDataCollector()
    success = collector.collect_all_scenarios()
    
    if success:
        print("\n✓ Data collection completed successfully!")
        print("\nNext steps:")
        print("  1. Review captured data in ml_dataset/")
        print("  2. Run ML pipeline: python main.py")
        print("  3. Train models on the collected data")
    else:
        print("\n✗ Data collection failed. Check errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
