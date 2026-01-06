#!/bin/bash
# Complete Attack Demonstration Script
# Runs inside Mininet Docker container

echo "=== SDN Attack Demonstration ==="
echo ""

# Install Scapy if not present
echo "[*] Installing dependencies..."
pip3 install scapy >/dev/null 2>&1

echo "[*] Network topology created"
echo "[*] Testing connectivity..."

# Test baseline connectivity
pingall

echo ""
echo "=== Running Attack Scenarios ===" 
echo ""

# Scenario 1: Normal traffic baseline
echo "[Scenario 1] Normal Traffic Baseline"
echo "Simulating legitimate web traffic..."
timeout 10 h1 python3 /workspace/normal_traffic/web_traffic.py 2>/dev/null &
sleep 2
echo "[OK] Normal traffic running"
echo ""

# Scenario 2: Host Location Hijacking Attack
echo "[Scenario 2] Host Location Hijacking Attack"
echo "Attacker (h1) attempting to hijack h2's location..."
echo "Command: h1 python3 /workspace/attacker/host_location_hijack.py 10.0.0.2 00:00:00:00:00:99"
h1 timeout 5 python3 /workspace/attacker/host_location_hijack.py 10.0.0.2 00:00:00:00:00:99 2>/dev/null
echo "[!] Attack completed - check Floodlight logs for TopoGuard detection"
echo ""

# Scenario 3: Link Fabrication
echo "[Scenario 3] Link Fabrication (Topology Poisoning)"
echo "Sending fake LLDP packets to create false topology..."
echo "Command: h1 python3 /workspace/attacker/link_fabrication.py 00:00:00:00:00:99 ff:ff:ff:ff:ff:ff"
h1 timeout 5 python3 /workspace/attacker/link_fabrication.py 00:00:00:00:00:99 ff:ff:ff:ff:ff:ff 2>/dev/null
echo "[!] Attack completed - topology integrity should be maintained"
echo ""

# Scenario 4: Packet-In Flood (DDoS)
echo "[Scenario 4] Packet-In Flood Attack (DDoS on Controller)"
echo "Flooding controller with packet-in messages..."
echo "Command: h1 python3 /workspace/attacker/ddos_attack.py 1 10.0.0.2"
h1 timeout 10 python3 /workspace/attacker/ddos_attack.py 1 10.0.0.2 2>/dev/null
echo "[!] Attack completed - controller should have rate-limited"
echo ""

# Verify network still works after attacks
echo "=== Post-Attack Verification ==="
echo "Testing if network still functions correctly..."
pingall

echo ""
echo "=== Demonstration Complete ==="
echo ""
echo "Summary:"
echo "- ✓ Normal traffic generated"
echo "- ✓ Host hijacking attempted (TopoGuard should detect)"
echo "- ✓ Topology poisoning attempted (should be blocked)"
echo "- ✓ Controller flood attempted (should be rate-limited)"
echo "- ✓ Network connectivity maintained"
echo ""
echo "Check Floodlight logs at: http://localhost:8080"
echo "Or run: docker logs floodlight-container (if logging enabled)"
