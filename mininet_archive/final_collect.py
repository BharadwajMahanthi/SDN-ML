#!/usr/bin/env python3
"""
Final Working Data Collector - Sustained Traffic Version
Keeps network alive with continuous ping to collect real flow data
"""

import requests
import pandas as pd
import time
import subprocess
import os
from datetime import datetime
import threading

print("""
╔══════════════════════════════════════════════════════════════╗
║     SDN Data Collection - SUSTAINED TRAFFIC VERSION         ║
║  Keeps network alive long enough to collect real flow data  ║
╚══════════════════════════════════════════════════════════════╝
""")

# Check Floodlight
print("\n[Check] Floodlight...")
try:
    r = requests.get("http://localhost:8080/wm/core/controller/summary/json", timeout=5)
    if r.status_code != 200:
        raise Exception("Not responding")
    print("  ✓ Ready")
except:
    print("  ✗ Floodlight not running!")
    exit(1)

# Start Mininet with SUSTAINED traffic
print("\n[Launch] Mininet with sustained ping traffic...")
print("  Duration: 40 seconds")

mininet_cmd = """
mn --switch user --controller=remote,ip=192.168.1.7,port=6653 --topo single,4 << 'EOF'
pingall
h1 ping -c 80 -i 0.5 h4 &
h2 ping -c 80 -i 0.5 h3 &
h3 ping -c 80 -i 0.5 h1 &
sleep 40
exit
EOF
"""

process = subprocess.Popen(
    ["docker", "run", "--rm", "--privileged", "mininet-custom", "bash", "-c", mininet_cmd],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

print("  - Waiting for network to start (15s)...")
time.sleep(15)

# Collect data
print("\n[Collect] Gathering flow statistics...")
all_data = []

for round_num in range(8):  # 8 rounds x 3 seconds = 24 seconds
    try:
        r = requests.get("http://localhost:8080/wm/core/switch/all/flow/json", timeout=3)
        if r.status_code == 200:
            flows = r.json()
            
            if flows:  # Not empty
                records = []
                for switch, flowlist in flows.items():
                    for flow in flowlist:
                        match = flow.get('match', {})
                        records.append({
                            'timestamp': datetime.now().isoformat(),
                            'switch': switch,
                            'priority': flow.get('priority', 0),
                            'duration': flow.get('durationSeconds', 0),
                            'packets': flow.get('packetCount', 0),
                            'bytes': flow.get('byteCount', 0),
                            'src_ip': match.get('networkSource', ''),
                            'dst_ip': match.get('networkDestination', ''),
                            'protocol': match.get('networkProtocol', ''),
                            'src_port': match.get('transportSource', ''),
                            'dst_port': match.get('transportDestination', ''),
                        })
                
                if records:
                    df = pd.DataFrame(records)
                    df['round'] = round_num
                    all_data.append(df)
                    print(f"  Round {round_num + 1}: Collected {len(df)} flows")
            else:
                print(f"  Round {round_num + 1}: No flows yet...")
    except Exception as e:
        print(f"  Round {round_num + 1}: Error - {e}")
    
    time.sleep(3)

# Stop Mininet
print("\n  - Stopping network...")
try:
    process.terminate()
    process.wait(timeout=10)
except:
    process.kill()

# Process results
print("\n[Results]")
if all_data:
    df = pd.concat(all_data, ignore_index=True)
    
    # Save
    filename = f"ml_dataset/sdn_flows_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    df.to_csv(filename, index=False)
    
    print(f"\n✅ SUCCESS!")
    print(f"  Records: {len(df)}")
    print(f"  File: {filename}")
    print(f"\n  Dataset Summary:")
    print(f"    Switches: {df['switch'].nunique()}")
    print(f"    IPs: {df['src_ip'].nunique()} sources → {df['dst_ip'].nunique()} destinations")
    print(f"    Traffic: {df['packets'].sum():,} packets, {df['bytes'].sum():,} bytes")
    print(f"\n  Sample:")
    print(df[['switch', 'src_ip', 'dst_ip', 'packets', 'bytes']].head())
    print(f"\n🎯 Ready for ML pipeline!")
    
else:
    print("❌ No data collected")
    print("\nLikely causes:")
    print("  - Switches didn't connect")
    print("  - Network finished too quickly")
    print("  - Check Floodlight logs")
