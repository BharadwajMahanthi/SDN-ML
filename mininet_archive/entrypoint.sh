#!/bin/bash

# ==========================================
# Robust Startup Script for Mininet+Floodlight
# Port: 6653 (Targeting the newly compiled JAR)
# Fixes: RTNETLINK File Exists + Derby DB Lock
# Fixes: Container Exit (Added exec "$@")
# ==========================================

# 1. CLEANUP DB LOCKS (Fixes crash)
rm -rf /var/lib/floodlight/SyncDB
rm -rf /var/lib/floodlight/db.lck
mkdir -p /var/lib/floodlight
chmod 777 /var/lib/floodlight

echo ">>> [0/4] Cleaning up stale network interfaces..."
ip link delete s1-eth1 2>/dev/null
ip link delete s1-eth2 2>/dev/null
ip link delete h1-eth0 2>/dev/null
ip link delete h2-eth0 2>/dev/null
ip link delete h3-eth0 2>/dev/null
ip link delete h4-eth0 2>/dev/null
ip link delete ovs-system 2>/dev/null
mn -c > /dev/null 2>&1 &
CLEANUP_PID=$!
sleep 2
kill -9 $CLEANUP_PID 2>/dev/null

echo ">>> [1/4] Starting Open vSwitch..."
service openvswitch-switch start > /dev/null 2>&1

echo ">>> [2/4] Starting Floodlight Controller (LOCAL/HOST)..."
HOST_JAR="/workspace/floodlight_with_topoguard/target/floodlight.jar"
if [ -f "$HOST_JAR" ]; then
    echo "    Using HOST-MOUNTED JAR: $HOST_JAR"
    RUN_JAR="$HOST_JAR"
    cd /workspace/floodlight_with_topoguard || exit
else
    echo "    WARNING: Host JAR not found. Using Image JAR."
    RUN_JAR="/home/floodlight_with_topoguard/target/floodlight.jar"
fi

java -jar "$RUN_JAR" > /var/log/floodlight.log 2>&1 &
PID=$!
echo "    Floodlight PID: $PID"

echo ">>> [3/4] Waiting for Port 6653 (OpenFlow)..."
READY=""
for i in {1..15}; do
    if netstat -tln | grep -q :6653; then
        echo "    Controller is UP (6653)!"
        READY=1
        break
    fi
     if netstat -tln | grep -q :6633; then
        echo "    Controller is UP (6633)!"
        READY=1
        break
    fi
     # Check if process died
    if ! kill -0 $PID 2>/dev/null; then
        echo "FAIL: Floodlight process died!"
        echo "=== LOG TAIL ==="
        tail -n 20 /var/log/floodlight.log
        exit 1
    fi
    echo -n "."
    sleep 2
done
echo ""

# Return to workspace for user
cd /workspace

# Keep container alive by running the command passed to docker run
# or falling back to bash if none provided
if [ -z "$1" ]; then
    exec /bin/bash
else
    exec "$@"
fi
