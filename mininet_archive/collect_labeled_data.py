#!/usr/bin/env python3
"""
Labeled SDN Data Collector
Automatically labels flows as normal (0) or attack (1) based on collection scenario
"""

import requests
import pandas as pd
import time
from datetime import datetime
import os
import sys

class LabeledDataCollector:
    def __init__(self):
        self.base_url = "http://localhost:8080/wm"
        self.dataset_dir = "ml_dataset"
        os.makedirs(self.dataset_dir, exist_ok=True)
    
    def collect_flows(self, duration=30, interval=3, label=0, scenario_name="normal"):
        """
        Collect flows with automatic labeling
        
        Args:
            duration: Collection duration in seconds
            interval: Collection interval in seconds
            label: 0 for normal, 1 for attack
            scenario_name: Description of scenario
        """
        print(f"\n{'='*70}")
        print(f"  Collecting: {scenario_name.upper()}")
        print(f"  Label: {label} ({'ATTACK' if label == 1 else 'NORMAL'})")
        print(f"  Duration: {duration}s | Interval: {interval}s")
        print(f"{'='*70}\n")
        
        all_data = []
        round_num = 0
        start_time = time.time()
        
        while (time.time() - start_time) < duration:
            try:
                response = requests.get(f"{self.base_url}/core/switch/all/flow/json", timeout=3)
                
                if response.status_code == 200:
                    flows_dict = response.json()
                    
                    if flows_dict and len(flows_dict) > 0:
                        records = []
                        
                        for switch_dpid, flow_list in flows_dict.items():
                            if not flow_list:
                                continue
                                
                            for flow in flow_list:
                                match = flow.get('match', {})
                                
                                record = {
                                    'timestamp': datetime.now().isoformat(),
                                    'switch': switch_dpid,
                                    'priority': flow.get('priority', 0),
                                    'duration_sec': flow.get('durationSeconds', 0),
                                    'idle_timeout': flow.get('idleTimeout', 0),
                                    'hard_timeout': flow.get('hardTimeout', 0),
                                    'packet_count': flow.get('packetCount', 0),
                                    'byte_count': flow.get('byteCount', 0),
                                    'in_port': match.get('inPort', ''),
                                    'src_mac': match.get('dataLayerSource', ''),
                                    'dst_mac': match.get('dataLayerDestination', ''),
                                    'src_ip': match.get('networkSource', ''),
                                    'dst_ip': match.get('networkDestination', ''),
                                    'protocol': match.get('networkProtocol', ''),
                                    'src_port': match.get('transportSource', ''),
                                    'dst_port': match.get('transportDestination', ''),
                                    'label': label,  # Auto-label!
                                    'scenario': scenario_name
                                }
                                records.append(record)
                        
                        if records:
                            df = pd.DataFrame(records)
                            all_data.append(df)
                            print(f"  Round {round_num + 1}: ✓ {len(records)} flows "
                                  f"({df['packet_count'].sum():,} packets, label={label})")
                            
            except Exception as e:
                print(f"  Round {round_num + 1}: ! Error: {e}")
            
            round_num += 1
            time.sleep(interval)
        
        if all_data:
            return pd.concat(all_data, ignore_index=True)
        return pd.DataFrame()

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║        LABELED SDN DATA COLLECTION - AUTO LABELING          ║
║                                                              ║
║  Collects flows with automatic labels:                      ║
║  • Normal traffic → Label 0                                 ║
║  • Attack traffic → Label 1                                 ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    collector = LabeledDataCollector()
    all_datasets = []
    
    # Scenario 1: Normal Traffic
    print("\n" + "🟢 "*35)
    print("SCENARIO 1: NORMAL TRAFFIC")
    print("🟢 "*35)
    print("\nInstructions:")
    print("  1. Make sure Mininet is running with normal ping traffic")
    print("  2. Press Enter when ready...")
    input()
    
    df_normal = collector.collect_flows(
        duration=30,
        interval=3,
        label=0,
        scenario_name="normal_traffic"
    )
    if not df_normal.empty:
        all_datasets.append(df_normal)
        print(f"\n✅ Collected {len(df_normal)} normal flow records")
    
    # Scenario 2: Host Hijacking Attack
    print("\n" + "🔴 "*35)
    print("SCENARIO 2: HOST LOCATION HIJACKING ATTACK")
    print("🔴 "*35)
    print("\nInstructions:")
    print("  1. In Mininet terminal, run:")
    print("     mininet> h1 python3 /workspace/attacker/host_location_hijack.py 10.0.0.2 00:00:00:00:00:99 &")
    print("  2. Press Enter when attack is running...")
    input()
    
    df_attack1 = collector.collect_flows(
        duration=30,
        interval=3,
        label=1,
        scenario_name="host_hijack_attack"
    )
    if not df_attack1.empty:
        all_datasets.append(df_attack1)
        print(f"\n✅ Collected {len(df_attack1)} attack flow records")
    
    # Scenario 3: Link Fabrication Attack
    print("\n" + "🔴 "*35)
    print("SCENARIO 3: LINK FABRICATION ATTACK")
    print("🔴 "*35)
    print("\nInstructions:")
    print("  1. In Mininet terminal, run:")
    print("     mininet> h1 python3 /workspace/attacker/link_fabrication.py 00:00:00:00:00:99 ff:ff:ff:ff:ff:ff &")
    print("  2. Press Enter when attack is running...")
    input()
    
    df_attack2 = collector.collect_flows(
        duration=30,
        interval=3,
        label=1,
        scenario_name="link_fabrication_attack"
    )
    if not df_attack2.empty:
        all_datasets.append(df_attack2)
        print(f"\n✅ Collected {len(df_attack2)} attack flow records")
    
    # Combine and save
    if all_datasets:
        print("\n" + "="*70)
        print("COMBINING DATASETS")
        print("="*70)
        
        final_df = pd.concat(all_datasets, ignore_index=True)
        
        # Save combined labeled dataset
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{collector.dataset_dir}/labeled_sdn_data_{timestamp}.csv"
        final_df.to_csv(filename, index=False)
        
        # Summary
        print(f"\n✅ SUCCESS! Created labeled dataset")
        print(f"\n📁 File: {filename}")
        print(f"📊 Total records: {len(final_df)}")
        print(f"\n📈 Label Distribution:")
        print(final_df['label'].value_counts())
        print(f"\n  0 (Normal): {len(final_df[final_df['label']==0])}")
        print(f"  1 (Attack): {len(final_df[final_df['label']==1])}")
        
        print(f"\n📊 Scenario Distribution:")
        print(final_df['scenario'].value_counts())
        
        print(f"\n🎯 Ready for ML Training!")
        print(f"\nNext step: python main.py")
        
    else:
        print("\n❌ No data collected")

if __name__ == "__main__":
    main()
