#!/usr/bin/env python3
"""
FIXED Live Data Collector - Properly handles flow JSON structure
The issue was checking if flows dict was truthy - empty dict is falsy!
"""

import requests
import pandas as pd
import time
from datetime import datetime
import os

def collect_live_data(duration=60, interval=3):
    print("\n" + "="*70)
    print("  FIXED LIVE SDN DATA COLLECTOR")
    print("="*70)
    print(f"\nDuration: {duration}s | Interval: {interval}s\n")
    
    base_url = "http://localhost:8080/wm"
    dataset_dir = "ml_dataset"
    os.makedirs(dataset_dir, exist_ok=True)
    
    all_data = []
    round_num = 0
    start_time = time.time()
    
    try:
        while (time.time() - start_time) < duration:
            try:
                response = requests.get(f"{base_url}/core/switch/all/flow/json", timeout=3)
                
                if response.status_code == 200:
                    flows_dict = response.json()
                    
                    # FIX: Check if dict has keys, not if dict is truthy!
                    if flows_dict and len(flows_dict) > 0:
                        records = []
                        
                        for switch_dpid, flow_list in flows_dict.items():
                            if not flow_list:  # Empty list for this switch
                                continue
                                
                            for flow in flow_list:
                                match = flow.get('match', {})
                                
                                record = {
                                    'timestamp': datetime.now().isoformat(),
                                    'round': round_num,
                                    'switch': switch_dpid,
                                    'priority': flow.get('priority', 0),
                                    'duration_sec': flow.get('durationSeconds', 0),
                                    'idle_timeout': flow.get('idleTimeout', 0),
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
                                }
                                records.append(record)
                        
                        if records:
                            df = pd.DataFrame(records)
                            all_data.append(df)
                            print(f"  Round {round_num + 1}: ✓ {len(records)} flows "
                                  f"({df['packet_count'].sum():,} packets, "
                                  f"{df['byte_count'].sum():,} bytes)")
                        else:
                            print(f"  Round {round_num + 1}: - No flow records")
                    else:
                        print(f"  Round {round_num + 1}: - No switches with flows")
                        
            except Exception as e:
                print(f"  Round {round_num + 1}: ! Error: {e}")
            
            round_num += 1
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n\n! Stopped by user")
    
    # Save results
    print("\n" + "="*70)
    print("RESULTS")
    print("="*70)
    
    if all_data:
        df = pd.concat(all_data, ignore_index=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{dataset_dir}/sdn_flows_{timestamp}.csv"
        df.to_csv(filename, index=False)
        
        print(f"\n✅ SUCCESS! Collected {len(df)} flow records")
        print(f"\n📁 File: {filename}")
        print(f"📊 Size: {os.path.getsize(filename) / 1024:.2f} KB")
        
        print(f"\n📈 Summary:")
        print(f"  Switches: {df['switch'].nunique()}")
        print(f"  Total packets: {df['packet_count'].sum():,}")
        print(f"  Total bytes: {df['byte_count'].sum():,}")
        print(f"  Unique IPs: {df['src_ip'].nunique()} → {df['dst_ip'].nunique()}")
        
        print(f"\n🔍 Top 5 Flows:")
        display_cols = ['switch', 'src_ip', 'dst_ip', 'protocol', 'packet_count', 'byte_count']
        print(df.nlargest(5, 'packet_count')[display_cols].to_string(index=False))
        
        print(f"\n🎯 Dataset ready for ML!")
        return True
    else:
        print("\n❌ No data collected")
        return False

if __name__ == "__main__":
    collect_live_data(duration=60, interval=3)
