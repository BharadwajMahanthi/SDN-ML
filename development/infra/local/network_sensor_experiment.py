#!/usr/bin/env python3
"""The network sensor against a real kernel, scored on independent truth.

The harness knows, without asking the sensor: which process connected, how
many times, where to, and what the server actually accepted. The sensor
produces only its own telemetry. The comparison happens afterwards.

Controls that must hold for any of this to mean anything:

* **false silence** -- run the identical traffic with the sensor stopped.
  Ground truth must still show the connections happened, the sensor must
  report zero, and health must say degraded rather than clean.
* **short-lived burst** -- 500 connections from a process that exits, which
  is the case `/proc` polling cannot see.
* **same-uid processes** -- two workloads under one uid, which containment
  cannot currently separate. Telemetry must.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone

# The package tree lives in different places depending on where this runs:
# mounted at /annulon in the Docker lab, unpacked to /opt/sdnguard/src on the
# AWS reference host. Hard-coding one of them made the experiment
# non-portable, and a reference run that cannot execute is not evidence about
# the reference platform.
for _candidate in (os.environ.get("ANNULON_SRC"),
                   "/annulon/development/src", "/opt/sdnguard/src"):
    if _candidate and os.path.isdir(os.path.join(_candidate, "annulon")):
        sys.path.insert(0, _candidate)
        break
else:
    raise SystemExit("cannot locate the annulon package; set ANNULON_SRC")

from annulon.network.contract import NetworkOperation                   # noqa: E402
from annulon.network.normalize import NetworkNormalizer                 # noqa: E402
from annulon.network.tracefs import (                                   # noqa: E402
    TracefsNetworkSensor, TracefsUnavailable,
)


class GroundTruthServer(threading.Thread):
    """Counts what it actually accepted. Produced by nobody's telemetry."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.accepted: list[tuple[str, int]] = []
        self._socket = socket.socket()
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(512)
        self.port = self._socket.getsockname()[1]
        self._stop = threading.Event()

    def run(self) -> None:
        self._socket.settimeout(0.2)
        while not self._stop.is_set():
            try:
                connection, address = self._socket.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
            self.accepted.append(address)
            connection.close()

    def stop(self) -> None:
        self._stop.set()
        self._socket.close()


_WORKLOAD = r"""
import json, os, socket, sys
port, count = int(sys.argv[1]), int(sys.argv[2])
stat = open("/proc/self/stat").read()
made = 0
for _ in range(count):
    s = socket.socket(); s.settimeout(2)
    try:
        s.connect(("127.0.0.1", port)); made += 1
    except Exception:
        pass
    finally:
        s.close()
print(json.dumps({"pid": os.getpid(),
                  "start_ticks": int(stat.split(")")[1].split()[19]),
                  "connections_made": made}))
"""


def run_workload(port: int, count: int, uid: int | None = None) -> dict:
    argv = [sys.executable, "-c", _WORKLOAD, str(port), str(count)]
    if uid is not None:
        argv = ["/usr/bin/setpriv", "--reuid", str(uid), "--regid", "nogroup",
                "--clear-groups"] + argv
    result = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    if result.returncode != 0:
        raise RuntimeError(f"workload failed: {result.stderr[:300]}")
    return json.loads(result.stdout.strip().splitlines()[-1])


def _count_for(events, pid: int) -> dict:
    """What the sensor saw for one process, by operation."""
    mine = [e for e in events if e.pid == pid]
    kinds = Counter(e.kind for e in mine)
    returns = Counter(e.fields.get("ret") for e in mine
                      if e.kind == "sys_exit_connect")
    return {"attempts": kinds.get("sys_enter_connect", 0),
            "results": kinds.get("sys_exit_connect", 0),
            "return_values": dict(returns)}


def run(count: int) -> dict:
    report: dict = {"environment": {
        "kernel": os.uname().release, "machine": os.uname().machine,
        "sensor": TracefsNetworkSensor.capability}}

    if not TracefsNetworkSensor.available():
        return {"completion": "EVIDENCE_INCOMPLETE",
                "reason": "; ".join(TracefsNetworkSensor.missing_requirements())}

    server = GroundTruthServer()
    server.start()

    # --- the sensor, observing a short-lived burst ------------------------
    sensor = TracefsNetworkSensor(buffer_kb=8192)
    sensor.start()
    time.sleep(0.4)
    started = time.monotonic()
    truth = run_workload(server.port, count)
    elapsed = time.monotonic() - started
    time.sleep(1.2)
    events = sensor.drain()
    health = sensor.health()
    observed = _count_for(events, truth["pid"])

    # --- normalised observations, scored on destination and process -------
    normalizer = NetworkNormalizer()
    observations = normalizer.normalize_all(events)
    attempts = [o for o in observations
                if o.operation is NetworkOperation.CONNECT_ATTEMPT]
    to_server = [o for o in attempts if o.remote and o.remote.port == server.port]
    correct_pid = [o for o in to_server if o.process.pid == truth["pid"]]
    established = [o for o in observations
                   if o.operation is NetworkOperation.CONNECTION_ESTABLISHED]
    # An ESTABLISHED transition in *task* context is legitimately
    # attributable -- on loopback the client's transition completes inline,
    # and measurement shows roughly half of them do. What must never happen
    # is a *softirq* event naming a process, and those are counted by the
    # normalizer as it discards them.
    attributed_established = [o for o in established
                              if o.process.confidence.value != "none"]
    softirq_named_a_process = [o for o in established
                               if o.process.confidence.value == "none"
                               and o.process.pid != 0]

    report["normalised_attribution"] = {
        "connect_attempts": len(attempts),
        "attempts_to_the_ground_truth_server": len(to_server),
        "attempts_with_the_correct_pid": len(correct_pid),
        "attribution_accuracy": (round(len(correct_pid) / len(to_server), 4)
                                 if to_server else None),
        "established_observations": len(established),
        "established_attributed_from_task_context": len(attributed_established),
        "softirq_events_whose_pid_was_discarded":
            normalizer.stats.unattributable_discarded_pid,
        "softirq_events_that_named_a_process": len(softirq_named_a_process),
        "normalizer_stats": normalizer.stats.to_dict(),
        "destination_sample": str(to_server[0].remote) if to_server else None,
        "note": "an ESTABLISHED transition in softirq has the context of "
                "whatever task was scheduled, so its pid is discarded. One "
                "in task context is attributable and is kept. The property "
                "under test is that no softirq event ever names a process.",
    }

    report["short_lived_burst"] = {
        "ground_truth_connections_made": truth["connections_made"],
        "ground_truth_server_accepted": len(server.accepted),
        "workload_pid": truth["pid"],
        "sensor_attempts_for_that_pid": observed["attempts"],
        "sensor_results_for_that_pid": observed["results"],
        "connect_return_values": observed["return_values"],
        "capture_rate": round(observed["attempts"] / count, 4) if count else None,
        "elapsed_seconds": round(elapsed, 3),
        "connections_per_second": round(count / elapsed, 1) if elapsed else None,
        "total_events_seen": len(events),
        "unparsed_lines": health["unparsed_lines"],
        "loss": health["loss"],
        "attests_completeness": health["attests_completeness"],
        "note": "the workload process has exited by the time this is scored",
    }

    # --- same-uid processes must stay distinguishable ---------------------
    before = len(server.accepted)
    first = run_workload(server.port, 5, uid=1500)
    second = run_workload(server.port, 7, uid=1500)
    time.sleep(1.0)
    events = sensor.drain()
    report["same_uid_processes"] = {
        "uid": 1500,
        "first": {"pid": first["pid"], "made": first["connections_made"],
                  "sensor_attempts": _count_for(events, first["pid"])["attempts"]},
        "second": {"pid": second["pid"], "made": second["connections_made"],
                   "sensor_attempts": _count_for(events, second["pid"])["attempts"]},
        "distinguishable": first["pid"] != second["pid"],
        "server_accepted": len(server.accepted) - before,
        "meaning": "detection separates these two workloads; containment by "
                   "meta skuid cannot. Detection precision exceeds current "
                   "enforcement precision, and that is recorded rather than "
                   "smoothed over.",
    }

    # --- FALSE SILENCE: the mandatory negative control ---------------------
    sensor.stop()
    before = len(server.accepted)
    silent_truth = run_workload(server.port, 50)
    time.sleep(0.8)
    silent_events = sensor.drain()
    silent_health = sensor.health()
    report["false_silence_control"] = {
        "sensor_stopped": True,
        "ground_truth_connections_made": silent_truth["connections_made"],
        "ground_truth_server_accepted": len(server.accepted) - before,
        "sensor_observations": len(silent_events),
        "health_running": silent_health["running"],
        "attests_completeness": silent_health["attests_completeness"],
        "degraded_reasons": silent_health["degraded_reasons"],
        "correct": (silent_truth["connections_made"] > 0
                    and len(silent_events) == 0
                    and not silent_health["attests_completeness"]),
        "meaning": "traffic demonstrably occurred and the sensor saw none of "
                   "it. Health must say degraded, never HEALTHY with zero "
                   "events.",
    }

    sensor.remove_instance()
    server.stop()
    report["verdict"] = _verdict(report, count)
    return report


def _verdict(report: dict, count: int) -> dict:
    burst = report["short_lived_burst"]
    same_uid = report["same_uid_processes"]
    silence = report["false_silence_control"]
    checks = {
        "burst_fully_captured": burst["sensor_attempts_for_that_pid"] >= count,
        "ground_truth_agrees": burst["ground_truth_server_accepted"] >= count,
        "no_loss_reported": burst["loss"]["lossless"],
        "sensor_attested_completeness": burst["attests_completeness"],
        "same_uid_processes_distinguishable": same_uid["distinguishable"],
        "destinations_resolved": (report["normalised_attribution"]
                                  ["attempts_to_the_ground_truth_server"] >= count),
        "attribution_accurate": (report["normalised_attribution"]
                                 ["attribution_accuracy"] == 1.0),
        "no_softirq_event_named_a_process": (report["normalised_attribution"]
                                             ["softirq_events_that_named_a_process"] == 0),
        "softirq_pids_were_actually_discarded": (report["normalised_attribution"]
                                                 ["softirq_events_whose_pid_was_discarded"] > 0),
        "same_uid_both_observed": (same_uid["first"]["sensor_attempts"] > 0
                                   and same_uid["second"]["sensor_attempts"] > 0),
        "false_silence_became_degraded": silence["correct"],
    }
    checks["completion"] = ("COMPLETE" if all(v for k, v in checks.items())
                            else "EVIDENCE_INCOMPLETE")
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=500)
    args = parser.parse_args()
    report = run(args.count)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("verdict", {}).get("completion") == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
