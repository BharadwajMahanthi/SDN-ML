import requests
import pandas as pd
import time
from datetime import datetime

# Floodlight REST API endpoint
CONTROLLER = 'http://localhost:8080'

def collect_flows(label):
    """Collect flow statistics from all switches"""
    try:
        # Get all switches
        switches_url = f'{CONTROLLER}/wm/core/controller/switches/json'
        switches = requests.get(switches_url).json()
        
        all_flows = []
        
        for switch in switches:
            dpid = switch['switchDPID']
            
            # Get flows for this switch
            flows_url = f'{CONTROLLER}/wm/core/switch/{dpid}/flow/json'
            flows = requests.get(flows_url).json()
            
            if dpid in flows:
                for flow in flows[dpid]:
                    flow_entry = {
                        'switch_dpid': dpid,
                        'src_ip': flow.get('match', {}).get('ipv4_src', '0.0.0.0'),
                        'dst_ip': flow.get('match', {}).get('ipv4_dst', '0.0.0.0'),
                        'src_port': flow.get('match', {}).get('tp_src', 0),
                        'dst_port': flow.get('match', {}).get('tp_dst', 0),
                       'protocol': flow.get('match', {}).get('ip_proto', 0),
                        'packet_count': flow.get('packetCount', 0),
                        'byte_count': flow.get('byteCount', 0),
                        'duration': flow.get('durationSeconds', 0),
                        'label': label
                    }
                    all_flows.append(flow_entry)
        
        return pd.DataFrame(all_flows)
    
    except Exception as e:
        print(f"Error collecting flows: {e}")
        return pd.DataFrame()

def main():
    print("=== SDN Flow Data Collector ===\n")
    
    # Collect normal traffic (label=0)
    print("[1/2] Waiting for normal traffic generation...")
    time.sleep(65)  # Wait for normal traffic script to complete
    
    print("Collecting normal traffic flows...")
    normal_flows = collect_flows(label=0)
    print(f"Collected {len(normal_flows)} normal flow entries")
    
    if len(normal_flows) > 0:
        normal_flows.to_csv('ml_dataset/normal_flows.csv', index=False)
        print("✓ Saved to ml_dataset/normal_flows.csv\n")
    
    # Collect attack traffic (label=1)
    print("[2/2] Waiting for attack simulation...")
    time.sleep(35)  # Wait for attack script
    
    print("Collecting attack traffic flows...")
    attack_flows = collect_flows(label=1)
    print(f"Collected {len(attack_flows)} attack flow entries")
    
    if len(attack_flows) > 0:
        attack_flows.to_csv('ml_dataset/attack_flows.csv', index=False)
        print("✓ Saved to ml_dataset/attack_flows.csv\n")
    
    # Combine datasets
    if len(normal_flows) > 0 and len(attack_flows) > 0:
        combined = pd.concat([normal_flows, attack_flows], ignore_index=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'ml_dataset/sdn_training_data_{timestamp}.csv'
        combined.to_csv(filename, index=False)
        print(f"✓ Combined dataset saved: {filename}")
        print(f"\nDataset Summary:")
        print(f"  Normal flows: {len(normal_flows)}")
        print(f"  Attack flows: {len(attack_flows)}")
        print(f"  Total: {len(combined)}")
    else:
        print("\n⚠ Warning: Insufficient data collected")

if __name__ == '__main__':
    main()
