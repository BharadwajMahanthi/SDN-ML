#!/bin/bash
# Simple Traffic Capture - Runs scenarios and captures with tshark
set -e

cd /workspace
CAPTURE_DIR="./captured_traffic"
mkdir -p $CAPTURE_DIR

echo "=== Starting Traffic Capture ==="
echo ""

# Start Mininet in background
echo "[*] Starting Mininet network..."
mn --switch user --controller=remote,ip=192.168.1.7,port=6653 --topo single,4 &
MN_PID=$!
sleep 15  # Wait for network to initialize

echo "[*] Network ready. Starting packet capture..."
echo ""

# Capture 1: Normal Baseline
echo "[Capture 1/4] Normal Traffic Baseline (60s)..."
tshark -i any -a duration:60 -w $CAPTURE_DIR/01_normal_baseline.pcap \
    -f "tcp or udp or icmp or arp" 2>/dev/null &
TSHARK_PID=$!
sleep 65
wait $TSHARK_PID 2>/dev/null || true
echo "  ✓ Saved: 01_normal_baseline.pcap"

# Capture 2: Web Traffic
echo "[Capture 2/4] Web Traffic Pattern (30s)..."
tshark -i any -a duration:30 -w $CAPTURE_DIR/02_web_traffic.pcap \
    -f "tcp port 80 or tcp port 443" 2>/dev/null &
sleep 35
echo "  ✓ Saved: 02_web_traffic.pcap"

# Capture 3: ARP Traffic (for host hijack detection)
echo "[Capture 3/4] ARP Traffic (30s)..."
tshark -i any -a duration:30 -w $CAPTURE_DIR/03_arp_traffic.pcap \
    -f "arp" 2>/dev/null &
sleep 35
echo "  ✓ Saved: 03_arp_traffic.pcap"

# Capture 4: Full Traffic Sample
echo "[Capture 4/4] Full Traffic Sample (60s)..."
tshark -i any -a duration:60 -w $CAPTURE_DIR/04_full_traffic.pcap 2>/dev/null &
sleep 65
echo "  ✓ Saved: 04_full_traffic.pcap"

# Convert to CSV
echo ""  
echo "[*] Converting PCAP to CSV..."
for pcap in $CAPTURE_DIR/*.pcap; do
    csv="${pcap%.pcap}.csv"
    tshark -r "$pcap" -T fields \
        -e frame.time_epoch -e ip.src -e ip.dst -e ip.proto \
        -e tcp.srcport -e tcp.dstport -e frame.len -e ip.ttl \
        -E header=y -E separator=, -E quote=d \
        > "$csv" 2>/dev/null || true
    echo "  ✓ Created: $(basename $csv)"
done

# Cleanup
kill $MN_PID 2>/dev/null || true

echo ""
echo "=== Capture Complete ==="
ls -lh $CAPTURE_DIR/
