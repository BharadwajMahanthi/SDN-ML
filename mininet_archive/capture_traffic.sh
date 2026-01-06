#!/bin/bash
# Packet Capture Script for SDN Traffic Data Collection
# Captures traffic using tshark and saves to PCAP files

CAPTURE_DIR="/workspace/captured_traffic"
DURATION=60  # Capture duration in seconds
INTERFACE="any"  # Capture on all interfaces

# Create capture directory
mkdir -p $CAPTURE_DIR

echo "=== SDN Traffic Data Collector ==="
echo "Capture Directory: $CAPTURE_DIR"
echo "Duration: ${DURATION}s per scenario"
echo ""

# Scenario 1: Normal Traffic
echo "[Scenario 1] Capturing Normal Traffic..."
tshark -i $INTERFACE -a duration:$DURATION -w $CAPTURE_DIR/normal_traffic.pcap \
    -f "tcp or udp or icmp" 2>/dev/null &
TSHARK_PID=$!

echo "  - Generating normal web traffic..."
timeout 30 python3 /workspace/normal_traffic/web_traffic.py 2>/dev/null &

echo "  - Generating IoT sensor traffic..."
timeout 30 python3 /workspace/normal_traffic/iot_traffic.py 2>/dev/null &

wait $TSHARK_PID
echo "  ✓ Normal traffic captured: $CAPTURE_DIR/normal_traffic.pcap"
echo ""

# Scenario 2: Host Location Hijacking Attack
echo "[Scenario 2] Capturing Host Location Hijacking Attack..."
tshark -i $INTERFACE -a duration:30 -w $CAPTURE_DIR/attack_host_hijack.pcap \
    -f "arp or tcp or udp" 2>/dev/null &
TSHARK_PID=$!

sleep 5
echo "  - Launching host hijacking attack..."
timeout 20 python3 /workspace/attacker/host_location_hijack.py 10.0.0.2 00:00:00:00:00:99 2>/dev/null

wait $TSHARK_PID
echo "  ✓ Attack traffic captured: $CAPTURE_DIR/attack_host_hijack.pcap"
echo ""

# Scenario 3: Link Fabrication Attack  
echo "[Scenario 3] Capturing Link Fabrication Attack..."
tshark -i $INTERFACE -a duration:30 -w $CAPTURE_DIR/attack_link_fabrication.pcap \
    -f "ether proto 0x88cc or tcp" 2>/dev/null &
TSHARK_PID=$!

sleep 5
echo "  - Launching link fabrication attack..."
timeout 20 python3 /workspace/attacker/link_fabrication.py 00:00:00:00:00:99 ff:ff:ff:ff:ff:ff 2>/dev/null

wait $TSHARK_PID
echo "  ✓ Attack traffic captured: $CAPTURE_DIR/attack_link_fabrication.pcap"
echo ""

# Scenario 4: DDoS Attack
echo "[Scenario 4] Capturing DDoS Attack..."
tshark -i $INTERFACE -a duration:30 -w $CAPTURE_DIR/attack_ddos.pcap 2>/dev/null &
TSHARK_PID=$!

sleep 5
echo "  - Launching DDoS attack..."
timeout 20 python3 /workspace/attacker/ddos_attack.py 1 10.0.0.2 2>/dev/null

wait $TSHARK_PID
echo "  ✓ Attack traffic captured: $CAPTURE_DIR/attack_ddos.pcap"
echo ""

# Convert PCAP to CSV for ML analysis
echo "[Data Processing] Converting PCAP files to CSV..."
for pcap_file in $CAPTURE_DIR/*.pcap; do
    csv_file="${pcap_file%.pcap}.csv"
    
    echo "  - Converting $(basename $pcap_file)..."
    tshark -r $pcap_file -T fields \
        -e frame.time_epoch \
        -e ip.src \
        -e ip.dst \
        -e ip.proto \
        -e tcp.srcport \
        -e tcp.dstport \
        -e udp.srcport \
       -e udp.dstport \
        -e frame.len \
        -e ip.ttl \
        -e tcp.flags \
        -E header=y \
        -E separator=, \
        -E quote=d \
        > $csv_file 2>/dev/null
    
    echo "    ✓ Created: $(basename $csv_file)"
done

echo ""
echo "=== Data Collection Complete ==="
echo "Captured Files:"
ls -lh $CAPTURE_DIR/
echo ""
echo "Files ready for ML analysis!"
