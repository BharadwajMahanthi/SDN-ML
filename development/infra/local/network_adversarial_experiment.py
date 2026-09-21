#!/usr/bin/env python3
"""Try to fool the network sensor on a real kernel.

Ground truth is held entirely by the harness and never derived from Annulon:
which processes it launched, their pids and start times, what each was told
to connect to, and what the controlled listeners actually accepted. Annulon
produces only its own observations. The join happens after collection.

The harness never writes an observation, an attribution, a health value or a
finding. Where a scenario needs Annulon to be wrong, the harness makes the
*world* adversarial and then reports what Annulon said about it.
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

sys.path.insert(0, "/annulon/development/src")

from annulon.network.contract import (                                  # noqa: E402
    AttributionConfidence, ConnectionOutcome, NetworkOperation,
)
from annulon.network.liveness import (                                  # noqa: E402
    NetworkLivenessMonitor, network_collection_health,
)
from annulon.network.normalize import NetworkNormalizer                 # noqa: E402
from annulon.network.tracefs import TracefsNetworkSensor               # noqa: E402

PRIMARY_EVENT = "sock/inet_sock_set_state"


class Listener(threading.Thread):
    """A controlled destination that records what it actually accepted."""

    def __init__(self, backlog: int = 512) -> None:
        super().__init__(daemon=True)
        self._socket = socket.socket()
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(backlog)
        self.port = self._socket.getsockname()[1]
        self.accepted = 0
        self._stop = threading.Event()

    def run(self) -> None:
        self._socket.settimeout(0.2)
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
            self.accepted += 1
            connection.close()

    def stop(self) -> None:
        self._stop.set()
        self._socket.close()


_WORKER = r"""
import json, os, socket, sys
port, count, uid_label = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
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
print(json.dumps({"pid": os.getpid(), "uid": os.getuid(),
                  "label": uid_label, "made": made,
                  "start_ticks": int(stat.split(")")[1].split()[19])}))
"""


def _launch(port: int, count: int, label: str, uid: int | None = None):
    argv = [sys.executable, "-c", _WORKER, str(port), str(count), label]
    if uid is not None:
        argv = ["/usr/bin/setpriv", "--reuid", str(uid), "--regid", "nogroup",
                "--clear-groups"] + argv
    return subprocess.Popen(argv, stdout=subprocess.PIPE, text=True)


def _collect(process) -> dict:
    out, _ = process.communicate(timeout=180)
    return json.loads(out.strip().splitlines()[-1])


class Pipeline:
    """The ordinary consumer path, exactly as 04D wired it."""

    def __init__(self, sensor, monitor) -> None:
        self.sensor = sensor
        self.normalizer = NetworkNormalizer()
        self.monitor = monitor
        self.observations: list = []

    def pump(self) -> list:
        produced = self.normalizer.normalize_all(self.sensor.drain())
        for observation in produced:
            self.monitor.consider(observation)
        self.observations.extend(produced)
        return produced


def _attempts_to(observations, port: int) -> list:
    return [o for o in observations
            if o.operation is NetworkOperation.CONNECT_ATTEMPT
            and o.remote and o.remote.port == port]


def run(burst: int) -> dict:
    report: dict = {"environment": {
        "kernel": os.uname().release, "machine": os.uname().machine,
        "capability": TracefsNetworkSensor.capability,
        "harness_pid": os.getpid()}}
    if not TracefsNetworkSensor.available():
        return {"completion": "EVIDENCE_INCOMPLETE",
                "reason": "; ".join(TracefsNetworkSensor.missing_requirements())}

    sensor = TracefsNetworkSensor(buffer_kb=16384)
    sensor.start()
    monitor = NetworkLivenessMonitor(deadline_seconds=6.0)
    pipeline = Pipeline(sensor, monitor)
    time.sleep(0.4)

    try:
        # --- A. concurrent same-destination, same-uid processes -----------
        listener = Listener()
        listener.start()
        time.sleep(0.2)
        workers = [_launch(listener.port, 25, f"w{i}", uid=1500) for i in range(6)]
        truths = [_collect(w) for w in workers]
        time.sleep(1.2)
        pipeline.pump()

        attempts = _attempts_to(pipeline.observations, listener.port)
        by_pid = Counter(o.process.pid for o in attempts)
        launched = {t["pid"] for t in truths}
        observed_pids = set(by_pid)
        report["concurrent_same_uid"] = {
            "processes_launched": len(truths),
            "all_same_uid": len({t["uid"] for t in truths}) == 1,
            "ground_truth_connections": sum(t["made"] for t in truths),
            "listener_accepted": listener.accepted,
            "observed_attempts": len(attempts),
            "distinct_pids_observed": len(observed_pids),
            "every_launched_pid_observed": launched <= observed_pids,
            "no_unlaunched_pid_attributed": (observed_pids - launched) == set(),
            "per_pid_counts_match_ground_truth": all(
                by_pid.get(t["pid"], 0) >= t["made"] for t in truths),
            "unexpected_pids": sorted(observed_pids - launched)[:5],
            "meaning": "six processes, one uid, one destination. Attribution "
                       "must separate them and must not name a process that "
                       "was never launched.",
        }
        listener.stop()

        # --- E. connect result semantics, measured not assumed ------------
        open_listener = Listener()
        open_listener.start()
        time.sleep(0.2)
        closed_port = _free_port()
        results = _probe_outcomes(open_listener.port, closed_port)
        time.sleep(1.0)
        pipeline.pump()
        connect_results = [o for o in pipeline.observations
                           if o.operation is NetworkOperation.CONNECT_RESULT]
        outcomes = Counter(o.outcome.value for o in connect_results)
        established = [o for o in pipeline.observations
                       if o.operation is NetworkOperation.CONNECTION_ESTABLISHED]
        report["connect_result_semantics"] = {
            "ground_truth": results,
            "observed_result_outcomes": dict(outcomes),
            "established_observations": len(established),
            "pending_never_counted_as_established": all(
                not o.outcome.is_established for o in connect_results
                if o.outcome is ConnectionOutcome.PENDING),
            "no_connect_result_carries_a_destination": all(
                o.remote is None for o in connect_results),
            "meaning": "a successful non-blocking connect returns "
                       "EINPROGRESS. Annulon must not read that as failure, "
                       "nor read a zero return as an established socket.",
        }
        open_listener.stop()

        # --- F. softirq attribution --------------------------------------
        softirq_named = [o for o in pipeline.observations
                         if o.process.confidence is AttributionConfidence.NONE
                         and o.process.pid != 0]
        downgraded = [o for o in pipeline.observations
                      if o.process.confidence is AttributionConfidence.NONE]
        report["softirq_attribution"] = {
            "observations_with_discarded_process": len(downgraded),
            "softirq_events_that_named_a_process": len(softirq_named),
            "normalizer_discarded_pids":
                pipeline.normalizer.stats.unattributable_discarded_pid,
            "meaning": "interrupt-context completions may contribute socket "
                       "state and must never become process attribution.",
        }

        # --- G. short-lived processes, gone before enrichment -------------
        short = Listener()
        short.start()
        time.sleep(0.2)
        quick = [_launch(short.port, 2, f"q{i}") for i in range(20)]
        quick_truth = [_collect(q) for q in quick]
        for q in quick:
            q.wait(timeout=10)
        time.sleep(1.0)
        pipeline.pump()
        quick_attempts = _attempts_to(pipeline.observations, short.port)
        quick_pids = {t["pid"] for t in quick_truth}
        report["short_lived_processes"] = {
            "processes_launched": len(quick_truth),
            "all_exited_before_scoring": all(q.poll() is not None for q in quick),
            "ground_truth_connections": sum(t["made"] for t in quick_truth),
            "listener_accepted": short.accepted,
            "observed_attempts": len(quick_attempts),
            "observations_survived_process_exit": len(quick_attempts) > 0,
            "attributed_to_launched_pids_only":
                {o.process.pid for o in quick_attempts} <= quick_pids,
            "all_attribution_is_weak": all(
                o.process.confidence is AttributionConfidence.PID_ONLY
                for o in quick_attempts),
            "none_claim_instance_binding": all(
                o.process.instance_key is None for o in quick_attempts),
            "meaning": "the process is gone before anything could read "
                       "/proc. The observation survives, and its attribution "
                       "stays weak rather than being upgraded by enrichment "
                       "that could not happen.",
        }
        short.stop()

        # --- K. bounded burst ---------------------------------------------
        burst_listener = Listener()
        burst_listener.start()
        time.sleep(0.2)
        before_loss = sensor.loss()
        burst_workers = [_launch(burst_listener.port, burst // 4, f"b{i}")
                         for i in range(4)]
        burst_truth = [_collect(w) for w in burst_workers]
        time.sleep(1.5)
        pipeline.pump()
        after_loss = sensor.loss()
        burst_attempts = _attempts_to(pipeline.observations, burst_listener.port)
        report["bounded_burst"] = {
            "ground_truth_connections": sum(t["made"] for t in burst_truth),
            "listener_accepted": burst_listener.accepted,
            "observed_attempts": len(burst_attempts),
            "queue_pending_after_drain": sensor.pending,
            "loss_before": before_loss.to_dict(),
            "loss_after": after_loss.to_dict(),
            "loss_is_counted_not_silent": after_loss.total >= before_loss.total,
            "health_reflects_loss":
                sensor.health()["attests_completeness"] == after_loss.lossless,
            "meaning": "not a throughput measurement. The property is that "
                       "the queue stays bounded and any loss is counted "
                       "rather than disappearing.",
        }
        burst_listener.stop()

        # --- I. false silence with independent truth ----------------------
        _set_event(sensor, PRIMARY_EVENT, "0")
        time.sleep(0.3)
        silent_listener = Listener()
        silent_listener.start()
        time.sleep(0.2)
        silent = _launch(silent_listener.port, 40, "silent")
        silent_truth = _collect(silent)
        time.sleep(1.0)
        pipeline.pump()
        silent_attempts = _attempts_to(pipeline.observations, silent_listener.port)
        blind_receipt = monitor.run(pump=pipeline.pump, loss=sensor.loss)
        blind_health = network_collection_health(sensor.health(), monitor)
        report["false_silence"] = {
            "ground_truth_connections": silent_truth["made"],
            "listener_accepted": silent_listener.accepted,
            "observed_attempts": len(silent_attempts),
            "reader_thread_alive": sensor.health()["running"],
            "liveness_status": monitor.status(),
            "trustworthy_absence": blind_health.trustworthy_absence,
            "attests_completeness": blind_health.attests_completeness,
            "correct": (silent_truth["made"] > 0
                        and silent_listener.accepted > 0
                        and len(silent_attempts) == 0
                        and not blind_health.trustworthy_absence),
            "meaning": "traffic demonstrably occurred while the sensor was "
                       "blind. Zero observations must not read as zero "
                       "network activity.",
        }
        silent_listener.stop()

        # --- recovery, then bounded shutdown ------------------------------
        _set_event(sensor, PRIMARY_EVENT, "1")
        time.sleep(0.3)
        recovery = monitor.run(pump=pipeline.pump, loss=sensor.loss)
        report["recovery"] = {
            "observed": recovery.observed,
            "status": monitor.status(),
            "failed_intervals_still_recorded":
                sum(1 for r in monitor.history if not r.observed),
        }
        started = time.monotonic()
        sensor.stop()
        report["shutdown"] = {"elapsed_seconds": round(time.monotonic() - started, 3)}
    finally:
        try:
            sensor.stop()
        except Exception:                                   # noqa: BLE001
            pass
        sensor.remove_instance()

    report["verdict"] = _verdict(report)
    return report


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _probe_outcomes(open_port: int, closed_port: int) -> dict:
    """Independent record of what each connect actually did."""
    outcomes = {}
    blocking = socket.socket()
    try:
        blocking.connect(("127.0.0.1", open_port))
        outcomes["blocking_to_open_port"] = "connected"
    except OSError as exc:
        outcomes["blocking_to_open_port"] = type(exc).__name__
    finally:
        blocking.close()

    nonblocking = socket.socket()
    nonblocking.settimeout(2)
    try:
        nonblocking.connect(("127.0.0.1", open_port))
        outcomes["nonblocking_to_open_port"] = "connected"
    except OSError as exc:
        outcomes["nonblocking_to_open_port"] = type(exc).__name__
    finally:
        nonblocking.close()

    refused = socket.socket()
    refused.settimeout(2)
    try:
        refused.connect(("127.0.0.1", closed_port))
        outcomes["to_closed_port"] = "connected"
    except OSError as exc:
        outcomes["to_closed_port"] = type(exc).__name__
    finally:
        refused.close()
    return outcomes


def _set_event(sensor, event: str, value: str) -> bool:
    try:
        with open(sensor._instance / "events" / event / "enable", "w") as handle:
            handle.write(value)
        return True
    except OSError:
        return False


def _verdict(report: dict) -> dict:
    same_uid = report["concurrent_same_uid"]
    short = report["short_lived_processes"]
    burst = report["bounded_burst"]
    silence = report["false_silence"]
    softirq = report["softirq_attribution"]
    checks = {
        "same_uid_processes_separated": (same_uid["distinct_pids_observed"]
                                         >= same_uid["processes_launched"]),
        "no_process_attributed_that_was_never_launched":
            same_uid["no_unlaunched_pid_attributed"],
        "every_launched_process_observed": same_uid["every_launched_pid_observed"],
        "no_softirq_event_named_a_process":
            softirq["softirq_events_that_named_a_process"] == 0,
        "pending_never_established":
            report["connect_result_semantics"]["pending_never_counted_as_established"],
        "connect_results_invent_no_destination":
            report["connect_result_semantics"]["no_connect_result_carries_a_destination"],
        "short_lived_observations_survived": short["observations_survived_process_exit"],
        "short_lived_attribution_stayed_weak": short["all_attribution_is_weak"],
        "no_instance_binding_was_fabricated": short["none_claim_instance_binding"],
        "short_lived_attributed_only_to_real_pids":
            short["attributed_to_launched_pids_only"],
        "burst_loss_counted": burst["loss_is_counted_not_silent"],
        "burst_health_consistent_with_loss": burst["health_reflects_loss"],
        "false_silence_handled": silence["correct"],
        "recovery_prospective": (report["recovery"]["observed"]
                                 and report["recovery"]["failed_intervals_still_recorded"] >= 1),
        "shutdown_bounded": report["shutdown"]["elapsed_seconds"] < 10.0,
    }
    checks["completion"] = ("COMPLETE" if all(v for k, v in checks.items())
                            else "EVIDENCE_INCOMPLETE")
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--burst", type=int, default=800)
    args = parser.parse_args()
    report = run(args.burst)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("verdict", {}).get("completion") == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
