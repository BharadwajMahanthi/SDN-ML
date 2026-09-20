#!/usr/bin/env bash
# Prove that lab traffic crosses the OVS datapath and NOT the EC2 management
# interface. A successful ping is not evidence on its own -- the legacy
# project's whole experiment ran over the management network while believing
# it was testing an SDN fabric. So this measures counters on both paths.
set -euo pipefail
BRIDGE="${BRIDGE:-br-s1}"

MGMT_IF="$(ip -o -4 route show to default | awk '{print $5}' | head -1)"

counter() { cat "/sys/class/net/$1/statistics/$2" 2>/dev/null || echo 0; }
ns_counter() { ip netns exec "$1" cat "/sys/class/net/$2/statistics/$3" 2>/dev/null || echo 0; }

echo "management interface (excluded from the experiment): $MGMT_IF"
echo

H1_TX_BEFORE=$(ns_counter h1 h1-eth0 tx_packets)
H2_RX_BEFORE=$(ns_counter h2 h2-eth0 rx_packets)
S1H1_RX_BEFORE=$(counter "${BRIDGE}-h1" rx_packets)
S1H2_TX_BEFORE=$(counter "${BRIDGE}-h2" tx_packets)
MGMT_RX_BEFORE=$(counter "$MGMT_IF" rx_packets)
MGMT_TX_BEFORE=$(counter "$MGMT_IF" tx_packets)

echo "running 20 ICMP echoes h1 -> h2 (10.10.0.2)"
ip netns exec h1 ping -c 20 -i 0.05 -W 1 10.10.0.2 | tail -3
echo

H1_TX_AFTER=$(ns_counter h1 h1-eth0 tx_packets)
H2_RX_AFTER=$(ns_counter h2 h2-eth0 rx_packets)
S1H1_RX_AFTER=$(counter "${BRIDGE}-h1" rx_packets)
S1H2_TX_AFTER=$(counter "${BRIDGE}-h2" tx_packets)
MGMT_RX_AFTER=$(counter "$MGMT_IF" rx_packets)
MGMT_TX_AFTER=$(counter "$MGMT_IF" tx_packets)

echo "================ packet counter deltas ================"
printf "%-34s %s\n" "h1 h1-eth0 tx"            "$((H1_TX_AFTER - H1_TX_BEFORE))"
printf "%-34s %s\n" "${BRIDGE}-h1 rx (into OVS)"  "$((S1H1_RX_AFTER - S1H1_RX_BEFORE))"
printf "%-34s %s\n" "${BRIDGE}-h2 tx (out of OVS)" "$((S1H2_TX_AFTER - S1H2_TX_BEFORE))"
printf "%-34s %s\n" "h2 h2-eth0 rx"            "$((H2_RX_AFTER - H2_RX_BEFORE))"
printf "%-34s %s\n" "$MGMT_IF rx (management)" "$((MGMT_RX_AFTER - MGMT_RX_BEFORE))"
printf "%-34s %s\n" "$MGMT_IF tx (management)" "$((MGMT_TX_AFTER - MGMT_TX_BEFORE))"
echo

echo "================ OVS kernel datapath flows ================"
ovs-dpctl dump-flows 2>/dev/null | grep -E "10\.10\.0|icmp|arp" | head -6 || \
  ovs-appctl dpctl/dump-flows | head -6
echo
echo "================ OpenFlow port statistics ================"
ovs-ofctl -O OpenFlow13 dump-ports br-s1 | grep -A2 -E "port +[1-4]" | head -14
echo
echo "================ proof the hosts have no route off the fabric ================"
echo "h1 routing table (only the lab subnet exists, no default route):"
ip netns exec h1 ip route show
echo "h1 cannot reach the management network:"
ip netns exec h1 ping -c 1 -W 1 169.254.169.254 >/dev/null 2>&1 && echo "REACHABLE - FABRIC IS LEAKING" || echo "unreachable (correct)"
