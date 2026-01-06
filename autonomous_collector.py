import requests
import pandas as pd
import time
import sys
from datetime import datetime

CONTROLLER = 'http://localhost:8080'

print("=== Waiting for SDN Lab Deployment ===")
print("Monitoring Floodlight for switch connection...")

# Wait for switch to connect
for attempt in range(30):
    try:
        resp = requests.get(f'{CONTROLLER}/wm/core/controller/switches/json', timeout=2)
        switches = resp.json()
        if len(switches) > 0:
            print(f"\n✓ Switch connected: {switches[0]['switchDPID']}")
            break
    except:
        pass
    print(f".", end='', flush=True)
    time.sleep(2)
else:
    print("\n✗ No switch detected after 60s. Check Floodlight logs.")
    sys.exit(1)

print("\n=== Starting Automated Data Collection ===\n")

def collect_flows(label_name):
    """Collect all flows and label them"""
    try:
        switches = requests.get(f'{CONTROLLER}/wm/core/controller/switches/json').json()
        all_flows = []
        
        for switch in switches:
            dpid = switch['switchDPID']
            flows_resp = requests.get(f'{CONTROLLER}/wm/core/switch/{dpid}/flow/json')
            flows_data = flows_resp.json()
            
            if dpid in flows_data:
                for flow in flows_data[dpid]:
                    match = flow.get('match', {})
                    all_flows.append({
                        'src_ip': match.get('ipv4_src', '0.0.0.0'),
                        'dst_ip': match.get('ipv4_dst', '0.0.0.0'),
                        'src_port': match.get('tp_src', 0),
                        'dst_port': match.get('tp_dst', 0),
                        'protocol': match.get('ip_proto', 0),
                        'packet_count': flow.get('packetCount', 0),
                        'byte_count': flow.get('byteCount', 0),
                        'duration': flow.get('durationSeconds', 0),
                        'label': label_name
                    })
        
        return pd.DataFrame(all_flows)
    except Exception as e:
        print(f"Error: {e}")
        return pd.DataFrame()

# Phase 1: Collect baseline (before traffic)
print("[1/3] Collecting baseline state...")
time.sleep(5)
baseline = collect_flows('baseline')
print(f"Baseline: {len(baseline)} flows\n")

# Phase 2: Wait for normal traffic generation
print("[2/3] Waiting for NORMAL traffic generation (70 seconds)...")
for i in range(14):
    print("." * 5, end='', flush=True)
    time.sleep(5)

normal_flows = collect_flows('normal')
print(f"\n✓ Collected {len(normal_flows)} normal flows\n")

# Phase 3: Wait for attack simulation
print("[3/3] Waiting for ATTACK simulation (40 seconds)...")
for i in range(8):
    print("." * 5, end='', flush=True)
    time.sleep(5)

attack_flows = collect_flows('attack')
print(f"\n✓ Collected {len(attack_flows)} attack flows\n")

# Save datasets
if len(normal_flows) > 0:
    normal_flows.to_csv('ml_dataset/normal_flows.csv', index=False)
    print("✓ Saved: ml_dataset/normal_flows.csv")

if len(attack_flows) > 0:
    attack_flows.to_csv('ml_dataset/attack_flows.csv', index=False)
    print("✓ Saved: ml_dataset/attack_flows.csv")

# Create labeled training dataset
if len(normal_flows) > 0 and len(attack_flows) > 0:
    # Binary labels: 0=normal, 1=attack
    normal_flows['binary_label'] = 0
    attack_flows['binary_label'] = 1
    
    combined = pd.concat([normal_flows, attack_flows], ignore_index=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'ml_dataset/sdn_training_{timestamp}.csv'
    combined.to_csv(filename, index=False)
    
    print(f"\n{'='*50}")
    print(f"✓ TRAINING DATASET CREATED: {filename}")
    print(f"{'='*50}")
    print(f"  Normal samples: {len(normal_flows)}")
    print(f"  Attack samples: {len(attack_flows)}")
    print(f"  Total samples: {len(combined)}")
    print(f"  Features: {list(combined.columns)}")
    print(f"\n✓ Ready for ML training!")
else:
    print("\n✗ Insufficient data collected. Check if traffic scripts ran.")

