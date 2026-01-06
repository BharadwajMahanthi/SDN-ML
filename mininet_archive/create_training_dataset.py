#!/usr/bin/env python3
"""
Create Final Labeled Training Dataset
Augments collected flow data with synthetic attack patterns
"""

import pandas as pd
import numpy as np
from datetime import datetime
import os

def create_training_dataset():
    """Create balanced labeled dataset from collected flows"""
    
    print("\n" + "="*70)
    print("  SDN ML TRAINING DATASET CREATOR")
    print("="*70)
    
    # Load collected data
    print("\n[Step 1] Loading collected flow data...")
    try:
        df_normal = pd.read_csv('ml_dataset/sdn_flows_20260105_174422.csv')
        print(f"  ✓ Loaded {len(df_normal)} flow records")
    except:
        print("  ✗ Could not find collected data")
        print("  Creating sample dataset instead...")
        df_normal = create_sample_normal_data()
    
    # Label normal data
    print("\n[Step 2] Labeling normal traffic...")
    df_normal['label'] = 0
    df_normal['attack_type'] = 'normal'
    print(f"  ✓ Labeled {len(df_normal)} records as NORMAL (0)")
    
    # Create attack variants
    print("\n[Step 3] Generating attack patterns...")
   
    all_attacks = []
    
    # Attack 1: High packet rate (DDoS)
    df_ddos = df_normal.copy()
    df_ddos['packet_count'] = df_ddos['packet_count'] * np.random.randint(50, 200, len(df_ddos))
    df_ddos['byte_count'] = df_ddos['byte_count'] * np.random.randint(50, 200, len(df_ddos))
    df_ddos['label'] = 1
    df_ddos['attack_type'] = 'ddos'
    all_attacks.append(df_ddos)
    print(f"  ✓ Created {len(df_ddos)} DDoS attack records")
    
    # Attack 2: Port scanning (unusual ports)
    df_portscan = df_normal.copy()
    df_portscan['src_port'] = np.random.randint(1024, 65535, len(df_portscan))
    df_portscan['dst_port'] = np.random.randint(1, 1024, len(df_portscan))
    df_portscan['packet_count'] = np.random.randint(1, 10, len(df_portscan))
    df_portscan['label'] = 1
    df_portscan['attack_type'] = 'port_scan'
    all_attacks.append(df_portscan)
    print(f"  ✓ Created {len(df_portscan)} port scan records")
    
    # Attack 3: Host hijacking (high priority flows)
    df_hijack = df_normal.copy()
    df_hijack['priority'] = np.random.randint(30000, 65000, len(df_hijack))
    df_hijack['duration_sec'] = 0  # New flows
    df_hijack['label'] = 1
    df_hijack['attack_type'] = 'host_hijack'
    all_attacks.append(df_hijack)
    print(f"  ✓ Created {len(df_hijack)} host hijacking records")
    
    # Combine all data
    print("\n[Step 4] Combining datasets...")
    final_df = pd.concat([df_normal] + all_attacks, ignore_index=True)
    print(f"  ✓ Total: {len(final_df)} records")
    
    # Shuffle
    final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save
    output_file = "ml_dataset/labeled_training_dataset.csv"
    final_df.to_csv(output_file, index=False)
    
    # Summary
    print("\n" + "="*70)
    print("SUCCESS!")
    print("="*70)
    print(f"\n📁 File: {output_file}")
    print(f"📊 Total Records: {len(final_df)}")
    print(f"\n📈 Label Distribution:")
    print(final_df['label'].value_counts())
    print(f"\n  0 (Normal): {len(final_df[final_df['label']==0])}")
    print(f"  1 (Attack): {len(final_df[final_df['label']==1])}")
    
    print(f"\n🎯 Attack Types:")
    print(final_df[final_df['label']==1]['attack_type'].value_counts())
    
    print(f"\n📝 Features: {list(final_df.columns)}")
    
    print(f"\n🎓 Ready for ML Training!")
    print(f"   Next: python main.py")
    
    return final_df

def create_sample_normal_data():
    """Create sample normal flow data if no collected data exists"""
    
    records = []
    for i in range(30):
        records.append({
            'timestamp': datetime.now().isoformat(),
            'round': i // 2,
            'switch': '00:00:00:00:00:00:00:01',
            'priority': np.random.randint(100, 1000),
            'duration_sec': i,
            'idle_timeout': 5,
            'hard_timeout': 0,
            'packet_count': np.random.randint(10, 200),
            'byte_count': np.random.randint(1000, 20000),
            'in_port': '',
            'src_mac': '',
            'dst_mac': '',
            'src_ip': '0.0.0.0',
            'dst_ip': '0.0.0.0',
            'protocol': '0',
            'src_port': '',
            'dst_port': '',
        })
    
    return pd.DataFrame(records)

if __name__ == "__main__":
    df = create_training_dataset()
    
    print(f"\n📋 Sample Data:")
    print(df.head(10))
