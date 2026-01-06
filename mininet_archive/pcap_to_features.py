#!/usr/bin/env python3
"""
PCAP to Feature Extraction for ML
Converts captured PCAP files to feature-rich CSV for machine learning
"""

import pyshark
import pandas as pd
import numpy as np
from datetime import datetime
import os
import sys

class PcapFeatureExtractor:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.features = []
        
    def extract_features(self):
        """Extract ML features from PCAP file"""
        print(f"[*] Processing: {os.path.basename(self.pcap_file)}")
        
        try:
            # Load PCAP file
            cap = pyshark.FileCapture(self.pcap_file, use_json=True, include_raw=True)
            
            packet_count = 0
            
            for packet in cap:
                try:
                    feature_dict = self._extract_packet_features(packet)
                    if feature_dict:
                        self.features.append(feature_dict)
                        packet_count += 1
                        
                        if packet_count % 100 == 0:
                            print(f"  [+] Processed {packet_count} packets...")
                            
                except Exception as e:
                    continue  # Skip malformed packets
            
            cap.close()
            print(f"  [✓] Extracted features from {packet_count} packets")
            
        except Exception as e:
            print(f"  [!] Error processing PCAP: {e}")
        
        return pd.DataFrame(self.features)
    
    def _extract_packet_features(self, packet):
        """Extract features from a single packet"""
        features = {}
        
        try:
            # Timestamp
            features['timestamp'] = float(packet.sniff_timestamp)
            
            # Frame info
            features['frame_len'] = int(packet.length)
            
            # IP layer
            if hasattr(packet, 'ip'):
                features['ip_src'] = packet.ip.src
                features['ip_dst'] = packet.ip.dst
                features['ip_proto'] = int(packet.ip.proto)
                features['ip_ttl'] = int(packet.ip.ttl)
                features['ip_len'] = int(packet.ip.len) if hasattr(packet.ip, 'len') else 0
            else:
                features['ip_src'] = '0.0.0.0'
                features['ip_dst'] = '0.0.0.0'
                features['ip_proto'] = 0
                features['ip_ttl'] = 0
                features['ip_len'] = 0
            
            # TCP layer
            if hasattr(packet, 'tcp'):
                features['tcp_srcport'] = int(packet.tcp.srcport)
                features['tcp_dstport'] = int(packet.tcp.dstport)
                features['tcp_flags'] = int(packet.tcp.flags, 16) if hasattr(packet.tcp, 'flags') else 0
                features['tcp_window'] = int(packet.tcp.window_size) if hasattr(packet.tcp, 'window_size') else 0
            else:
                features['tcp_srcport'] = 0
                features['tcp_dstport'] = 0
                features['tcp_flags'] = 0
                features['tcp_window'] = 0
            
            # UDP layer
            if hasattr(packet, 'udp'):
                features['udp_srcport'] = int(packet.udp.srcport)
                features['udp_dstport'] = int(packet.udp.dstport)
                features['udp_len'] = int(packet.udp.length)
            else:
                features['udp_srcport'] = 0
                features['udp_dstport'] = 0
                features['udp_len'] = 0
            
            # ICMP
            if hasattr(packet, 'icmp'):
                features['icmp_type'] = int(packet.icmp.type)
                features['icmp_code'] = int(packet.icmp.code) if hasattr(packet.icmp, 'code') else 0
            else:
                features['icmp_type'] = 0
                features['icmp_code'] = 0
            
            # ARP
            if hasattr(packet, 'arp'):
                features['arp_opcode'] = int(packet.arp.opcode)
                features['arp_src_mac'] = packet.arp.src_hw_mac if hasattr(packet.arp, 'src_hw_mac') else '00:00:00:00:00:00'
            else:
                features['arp_opcode'] = 0
                features['arp_src_mac'] = '00:00:00:00:00:00'
            
            return features
            
        except Exception as e:
            return None

def process_all_pcaps(input_dir, output_dir):
    """Process all PCAP files in directory"""
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    pcap_files = [f for f in os.listdir(input_dir) if f.endswith('.pcap')]
    
    print(f"\n=== PCAP Feature Extraction ===")
    print(f"Input Directory: {input_dir}")
    print(f"Output Directory: {output_dir}")
    print(f"Files to process: {len(pcap_files)}\n")
    
    for pcap_file in pcap_files:
        pcap_path = os.path.join(input_dir, pcap_file)
        
        # Extract features
        extractor = PcapFeatureExtractor(pcap_path)
        df = extractor.extract_features()
        
        if not df.empty:
            # Add label based on filename
            if 'attack' in pcap_file.lower():
                df['label'] = 'attack'
                if 'hijack' in pcap_file.lower():
                    df['attack_type'] = 'host_hijack'
                elif 'fabrication' in pcap_file.lower():
                    df['attack_type'] = 'link_fabrication'
                elif 'ddos' in pcap_file.lower():
                    df['attack_type'] = 'ddos'
                else:
                    df['attack_type'] = 'unknown'
            else:
                df['label'] = 'normal'
                df['attack_type'] = 'none'
            
            # Save to CSV
            output_file = os.path.join(output_dir, pcap_file.replace('.pcap', '_features.csv'))
            df.to_csv(output_file, index=False)
            print(f"  [✓] Saved: {os.path.basename(output_file)} ({len(df)} records)\n")
    
    print("=== Feature Extraction Complete ===\n")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        input_dir = sys.argv[1]
    else:
        input_dir = "captured_traffic"
    
    output_dir = "ml_dataset"
    
    try:
        process_all_pcaps(input_dir, output_dir)
    except Exception as e:
        print(f"[!] Error: {e}")
        print("\nNote: This script requires pyshark. Install with:")
        print("  pip install pyshark")
