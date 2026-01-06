#!/bin/bash
# Simulate MAC spoofing attack

echo "=== Starting Attack Traffic Capture ==="

# Start packet capture
docker exec -d clab-sdn-simple-switch tcpdump -i any -w /tmp/attack.pcap -c 200

sleep 2

# Get h1's MAC and IP
H1_MAC=$(docker exec clab-sdn-simple-h1 cat /sys/class/net/eth0/address)
echo "H1 MAC address: $H1_MAC"

# Attack: h4 changes its MAC to match h1
echo "h4 spoofing h1's MAC address..."
docker exec clab-sdn-simple-h4 ip link set eth0 down
docker exec clab-sdn-simple-h4 ip link set eth0 address $H1_MAC
docker exec clab-sdn-simple-h4 ip link set eth0 up

# h4 sends traffic (appears as h1)
echo "Generating spoofed traffic..."
docker exec clab-sdn-simple-h4 ping -c 20 172.17.0.4 &
docker exec clab-sdn-simple-h4 ping -c 20 172.17.0.3 &

wait

sleep 3

# Copy pcap to Windows
docker cp clab-sdn-simple-switch:/tmp/attack.pcap /mnt/c/Users/mbpd1/Downloads/SDN-ML/attack.pcap

echo "✓ Attack traffic saved: attack.pcap"
