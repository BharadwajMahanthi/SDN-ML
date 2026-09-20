#!/usr/bin/env bash
# Emit the lab's environment and topology as JSON, for the evidence bundle.
# Contains provenance only -- no packet payloads, no credentials.
set -euo pipefail
BRIDGE="${BRIDGE:-br-s1}"

ports_json() {
  local first=1; printf '['
  for h in h1 h2 h3 h4; do
    [ $first -eq 1 ] || printf ','; first=0
    printf '{"host":"%s","ofport":%s,"ovs_interface":"%s-%s","host_interface":"%s-eth0","mac":"%s","ipv4":"%s"}' \
      "$h" "$(ovs-vsctl get interface ${BRIDGE}-$h ofport)" "$BRIDGE" "$h" "$h" \
      "$(ip netns exec $h cat /sys/class/net/${h}-eth0/address)" \
      "$(ip netns exec $h ip -o -4 addr show ${h}-eth0 | awk '{print $4}')"
  done
  printf ']'
}

cat <<JSON
{
  "captured_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "environment": {
    "distribution": "$(. /etc/os-release; echo "$NAME $VERSION")",
    "distribution_id": "$(. /etc/os-release; echo "$VERSION_ID")",
    "kernel": "$(uname -r)",
    "architecture": "$(uname -m)",
    "ovs_version": "$(ovs-vsctl --version | head -1 | awk '{print $NF}')",
    "ovs_service_state": "$(systemctl is-active openvswitch-switch)",
    "openvswitch_kmod_loaded": $(lsmod | grep -qc '^openvswitch' && echo true || echo false),
    "datapath_types": "$(ovs-vsctl get Open_vSwitch . datapath_types | tr -d '\"')",
    "python_version": "$(/opt/sdnguard/venv/bin/python --version | awk '{print $2}')",
    "os_ken_version": "$(/opt/sdnguard/venv/bin/pip show os-ken | awk -F': ' '/^Version/{print $2}')",
    "eventlet_version": "$(/opt/sdnguard/venv/bin/pip show eventlet | awk -F': ' '/^Version/{print $2}')",
    "management_interface": "$(ip -o -4 route show to default | awk '{print $5}' | head -1)"
  },
  "topology": {
    "bridge": "$BRIDGE",
    "datapath_id": "$(ovs-ofctl -O OpenFlow13 show $BRIDGE | grep -o 'dpid:[0-9a-f]*' | cut -d: -f2)",
    "openflow_protocols": "$(ovs-vsctl get bridge $BRIDGE protocols | tr -d '[]\"')",
    "subnet": "10.10.0.0/24",
    "ports": $(ports_json)
  }
}
JSON
