#!/bin/bash
# Continuous Traffic Generator for SDN Data Collection
# Uses iperf for real TCP/UDP data streams between hosts

echo "=== SDN Continuous Traffic Generator ==="
echo ""

# Start Mininet
mn --switch user --controller=remote,ip=192.168.1.7,port=6653 --topo single,4 << 'MININET_EOF'

# Wait for network to initialize
sleep 2

# Initial connectivity test
pingall

echo ""
echo "=== Starting Continuous Traffic Flows ==="
echo ""

# Start iperf servers on receiving hosts
echo "[1/4] Starting iperf servers..."
h2 iperf -s -p 5001 > /tmp/h2_iperf.log 2>&1 &
h3 iperf -s -p 5002 > /tmp/h3_iperf.log 2>&1 &
h1 iperf -s -p 5003 > /tmp/h1_iperf.log 2>&1 &
h4 iperf -s -p 5004 > /tmp/h4_iperf.log 2>&1 &

sleep 3

# Start iperf clients (continuous traffic)
echo "[2/4] Starting traffic flows..."
echo "  h1 → h2 (TCP stream)"
h1 iperf -c 10.0.0.2 -p 5001 -t 60 -i 5 > /tmp/h1_to_h2.log 2>&1 &

echo "  h2 → h3 (TCP stream)"
h2 iperf -c 10.0.0.3 -p 5002 -t 60 -i 5 > /tmp/h2_to_h3.log 2>&1 &

echo "  h4 → h1 (TCP stream)"
h4 iperf -c 10.0.0.1 -p 5003 -t 60 -i 5 > /tmp/h4_to_h1.log 2>&1 &

echo "  h3 → h4 (TCP stream)"
h3 iperf -c 10.0.0.4 -p 5004 -t 60 -i 5 > /tmp/h3_to_h4.log 2>&1 &

echo ""
echo "=== Traffic Flowing ==="
echo "Duration: 60 seconds"
echo "Flows: h1→h2, h2→h3, h4→h1, h3→h4"
echo ""
echo "Now collecting data in another terminal:"
echo "  python collect_live_data.py"
echo ""
echo "Or capture with Wireshark/tcpdump!"
echo ""

# Keep network alive
sleep 60

echo ""
echo "=== Traffic Complete ==="
echo ""

# Show stats
echo "Traffic Statistics:"
h1 cat /tmp/h1_to_h2.log | tail -3
h2 cat /tmp/h2_to_h3.log | tail -3

exit

MININET_EOF
