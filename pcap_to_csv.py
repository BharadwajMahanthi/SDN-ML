from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import pandas as pd
import os

def extract_features(pcap_file, label):
    """Extract network features from pcap file"""
    print(f"Processing {pcap_file}...")
    
    if not os.path.exists(pcap_file):
        print(f"File not found: {pcap_file}")
        return pd.DataFrame()
    
    packets = rdpcap(pcap_file)
    features = []
    
    for pkt in packets:
        if IP in pkt:
            feature = {
                'src_ip': pkt[IP].src,
                'dst_ip': pkt[IP].dst,
                'protocol': pkt[IP].proto,
                'packet_len': len(pkt),
                'ttl': pkt[IP].ttl,
                'src_port': 0,
                'dst_port': 0,
                'label': label
            }
            
            if TCP in pkt:
                feature['src_port'] = pkt[TCP].sport
                feature['dst_port'] = pkt[TCP].dport
                feature['flags'] = pkt[TCP].flags
            elif UDP in pkt:
                feature['src_port'] = pkt[UDP].sport
                feature['dst_port'] = pkt[UDP].dport
                feature['flags'] = 0
            else:
                feature['flags'] = 0
                
            features.append(feature)
    
    return pd.DataFrame(features)

print("=== Converting PCAP to CSV ===\n")

# Process normal traffic
normal_df = extract_features('normal.pcap', label=0)
print(f"Normal traffic: {len(normal_df)} packets\n")

# Process attack traffic
attack_df = extract_features('attack.pcap', label=1)
print(f"Attack traffic: {len(attack_df)} packets\n")

# Combine datasets
if len(normal_df) > 0 and len(attack_df) > 0:
    combined = pd.concat([normal_df, attack_df], ignore_index=True)
    
    # Save to ml_dataset
    os.makedirs('ml_dataset', exist_ok=True)
    output_file = 'ml_dataset/sdn_training_data.csv'
    combined.to_csv(output_file, index=False)
    
    print(f"✓ Training dataset created: {output_file}")
    print(f"\nDataset Summary:")
    print(f"  Total samples: {len(combined)}")
    print(f"  Normal (label=0): {len(normal_df)}")
    print(f"  Attack (label=1): {len(attack_df)}")
    print(f"  Features: {list(combined.columns)}")
    print(f"\n✓ Ready for ML training!")
else:
    print("✗ Error: No data captured")
