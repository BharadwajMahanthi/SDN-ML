#!/bin/bash
# Deploy SDN lab and run full data generation pipeline

set -e  # Exit on error

echo "=== SDN Attack Lab - Full Pipeline ==="
echo ""

# Step 1: Deploy topology
echo "[1/5] Deploying Containerlab topology..."
sudo containerlab deploy -t /mnt/c/Users/mbpd1/Downloads/SDN-ML/sdn_topology.clab.yml

# Wait for containers to be ready
sleep 5

# Step 2: Verify connectivity
echo ""
echo "[2/5] Verifying OVS switch connection..."
docker exec clab-sdn-attack-lab-ovs1 ovs-vsctl show

# Step 3: Generate normal traffic
echo ""
echo "[3/5] Generating normal traffic (60 seconds)..."
bash /mnt/c/Users/mbpd1/Downloads/SDN-ML/generate_normal_traffic.sh

# Step 4: Simulate attack
echo ""
echo "[4/5] Simulating Host Location Hijack attack (30 seconds)..."
bash /mnt/c/Users/mbpd1/Downloads/SDN-ML/simulate_attack.sh

# Step 5: Cleanup
echo ""
echo "[5/5] Data generation complete!"
echo "Check Windows for collected data files."
echo ""
echo "To destroy lab: sudo containerlab destroy -t /mnt/c/Users/mbpd1/Downloads/SDN-ML/sdn_topology.clab.yml"
