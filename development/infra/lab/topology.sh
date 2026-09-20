#!/usr/bin/env bash
# Build the sdnguard P6 lab topology inside a single Linux host.
#
#   h1 ... h4   network namespaces, explicit lab-only addressing 10.10.0.0/24
#     |
#   veth pairs  named explicitly on both ends -- never discovered by guessing
#     |
#   br-s1       OVS bridge with a pinned 64-bit datapath id
#
# The EC2/VPC interface is deliberately untouched. It is the host's management
# path and is never part of the experiment's data plane.
set -euo pipefail

BRIDGE="${BRIDGE:-br-s1}"
DPID="${DPID:-0000aabbccddeeff}"     # a real 64-bit DPID, far outside Java's
                                     # boxed-integer cache range (KF-07)
SUBNET_PREFIX="${SUBNET_PREFIX:-10.10.0}"
HOSTS="${HOSTS:-h1 h2 h3 h4}"

log() { echo "[topology] $*"; }

create() {
  log "creating bridge $BRIDGE with datapath-id $DPID"
  ovs-vsctl --may-exist add-br "$BRIDGE"
  ovs-vsctl set bridge "$BRIDGE" other-config:datapath-id="$DPID"
  ovs-vsctl set bridge "$BRIDGE" protocols=OpenFlow13
  ip link set "$BRIDGE" up

  local index=0
  for host in $HOSTS; do
    index=$((index + 1))
    local host_if="${host}-eth0"          # inside the namespace
    local ovs_if="${BRIDGE}-${host}"      # on the bridge
    local addr="${SUBNET_PREFIX}.${index}/24"

    log "creating namespace $host  ${host_if} <-> ${ovs_if}  ${addr}"
    ip netns add "$host"
    ip link add "$host_if" type veth peer name "$ovs_if"
    ip link set "$host_if" netns "$host"

    # A deterministic MAC per host: 02 = locally administered, then the index.
    ip netns exec "$host" ip link set "$host_if" address "02:00:00:00:00:0${index}"
    ip netns exec "$host" ip addr add "$addr" dev "$host_if"
    ip netns exec "$host" ip link set "$host_if" up
    ip netns exec "$host" ip link set lo up

    ovs-vsctl --may-exist add-port "$BRIDGE" "$ovs_if" -- \
      set interface "$ovs_if" ofport_request="$index"
    ip link set "$ovs_if" up
  done
  log "created"
}

destroy() {
  for host in $HOSTS; do
    ip netns del "$host" 2>/dev/null || true
    ip link del "${BRIDGE}-${host}" 2>/dev/null || true
  done
  ovs-vsctl --if-exists del-br "$BRIDGE"
  log "destroyed"
}

case "${1:-create}" in
  create)  create ;;
  destroy) destroy ;;
  recreate) destroy; create ;;
  *) echo "usage: $0 {create|destroy|recreate}" >&2; exit 2 ;;
esac
