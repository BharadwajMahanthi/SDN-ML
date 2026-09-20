#!/usr/bin/env bash
# Run one controlled experiment on the lab host.
#
# The rule this encodes: never infer that the controller and switch are
# talking. Start the controller, force the switch to reconnect, then *wait for
# a normalised switch_connected event to appear in the journal* before the
# scenario runs. If that event never arrives the experiment aborts rather than
# producing a run whose silence could be mistaken for a negative result.
set -euo pipefail

RUN_ID="${RUN_ID:?RUN_ID required}"
SCENARIO="${SCENARIO:-/opt/sdnguard/scenario.sh}"
SECONDS_TO_RUN="${SECONDS_TO_RUN:-60}"
CONTROLLER_ARGS="${CONTROLLER_ARGS:-}"
EVIDENCE="/opt/sdnguard/evidence/$RUN_ID"

say() { echo "[experiment] $*"; }

# 1. no stale controller, and the port must actually be free
# KF-22: escalate. A controller that ignores SIGTERM must not be able to
# leave a bound port behind and void the next experiment.
pkill -TERM -f run_controller.py 2>/dev/null || true
sleep 2
pkill -KILL -f run_controller.py 2>/dev/null || true
for _ in $(seq 1 30); do
  ss -ltn 2>/dev/null | grep -q ':6653 ' || break
  sleep 1
done
if ss -ltn 2>/dev/null | grep -q ':6653 '; then
  say "ABORT: port 6653 still bound"; exit 1
fi

rm -rf "$EVIDENCE"; mkdir -p "$EVIDENCE"

# 2. start the controller
SDNGUARD_SRC=/opt/sdnguard/src nohup /opt/sdnguard/venv/bin/python \
  /opt/sdnguard/run_controller.py --evidence "$EVIDENCE" \
  --seconds "$SECONDS_TO_RUN" $CONTROLLER_ARGS \
  > "$EVIDENCE/controller.log" 2>&1 &
CONTROLLER_PID=$!
say "controller pid $CONTROLLER_PID"

for _ in $(seq 1 30); do
  ss -ltn 2>/dev/null | grep -q ':6653 ' && break
  sleep 1
done
ss -ltn 2>/dev/null | grep -q ':6653 ' || { say "ABORT: controller never listened"; exit 1; }
say "controller is listening on 6653"

# 3. force a fresh OpenFlow handshake rather than waiting out OVS backoff
ovs-vsctl set bridge br-s1 protocols=OpenFlow13
ovs-vsctl del-controller br-s1 2>/dev/null || true
ovs-vsctl set-controller br-s1 tcp:127.0.0.1:6653
ovs-vsctl set-fail-mode br-s1 secure

# 4. WAIT FOR PROOF, do not assume
CONNECTED=0
for _ in $(seq 1 40); do
  if grep -q '"kind": "switch_connected"' "$EVIDENCE/controller_events.jsonl" 2>/dev/null; then
    CONNECTED=1; break
  fi
  sleep 1
done
if [ "$CONNECTED" != "1" ]; then
  say "ABORT: no normalised switch_connected event within 40s"
  say "ovs view:"; ovs-vsctl -f table --columns=target,is_connected,status list Controller
  tail -20 "$EVIDENCE/controller.log"
  kill "$CONTROLLER_PID" 2>/dev/null || true
  exit 1
fi
say "switch registered with the controller (normalised event observed)"

# 5. capture flow state, run the scenario, capture it again
ovs-ofctl -O OpenFlow13 dump-flows br-s1 > "$EVIDENCE/flow_state_before.txt" 2>&1 || true
ovs-ofctl -O OpenFlow13 dump-ports br-s1 > "$EVIDENCE/port_stats_before.txt" 2>&1 || true

if [ -x "$SCENARIO" ]; then
  say "running scenario $SCENARIO"
  EVIDENCE_DIR="$EVIDENCE" "$SCENARIO" 2>&1 | tee "$EVIDENCE/scenario.log" || true
else
  say "no scenario supplied; idling"
fi

ovs-ofctl -O OpenFlow13 dump-flows br-s1 > "$EVIDENCE/flow_state_after.txt" 2>&1 || true
ovs-ofctl -O OpenFlow13 dump-ports br-s1 > "$EVIDENCE/port_stats_after.txt" 2>&1 || true

# 6. stop cleanly so the controller writes its health record
say "stopping controller"
kill -TERM "$CONTROLLER_PID" 2>/dev/null || true
for _ in $(seq 1 20); do kill -0 "$CONTROLLER_PID" 2>/dev/null || break; sleep 1; done
kill -9 "$CONTROLLER_PID" 2>/dev/null || true
if ss -ltn 2>/dev/null | grep -q ':6653 '; then
  say "WARNING: port 6653 still bound after stop"
fi
say "done: $EVIDENCE"
