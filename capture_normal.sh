#!/bin/bash
# Capture normal network traffic

echo "=== Starting Normal Traffic Capture ==="

# Start packet capture on switch
docker exec -d clab-sdn-simple-switch tcpdump -i any -w /tmp/normal.pcap -c 300

sleep 2

# Generate normal ping traffic
echo "Generating ICMP traffic..."
docker exec clab-sdn-simple-h1 ping -c 25 172.17.0.4 > /dev/null 2>&1 &
docker exec clab-sdn-simple-h2 ping -c 25 172.17.0.3 > /dev/null 2>&1 &
docker exec clab-sdn-simple-h3 ping -c 25 172.17.0.2 > /dev/null 2>&1 &

sleep 10

# Generate TCP traffic
echo "Generating TCP traffic..."
for i in {1..10}; do
    docker exec clab-sdn-simple-h1 timeout 1 nc -zv 172.17.0.4 80 2>/dev/null || true
    docker exec clab-sdn-simple-h2 timeout 1 nc -zv 172.17.0.3 22 2>/dev/null || true
    sleep 0.5
done

wait

sleep 3

# Copy pcap to Windows
docker cp clab-sdn-simple-switch:/tmp/normal.pcap /mnt/c/Users/mbpd1/Downloads/SDN-ML/normal.pcap

echo "✓ Normal traffic saved: normal.pcap"
