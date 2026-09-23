#!/usr/bin/env python3
"""Load and soak, measured as security properties rather than throughput.

`SAFE-LOAD-01` and `SAFE-SOAK-01` are not benchmarks. No number produced here
is a product target, and the acceptance criteria say so. What is under test
is narrower and more important:

**Under load, does the system stay honest?** A sensor that quietly drops
events while still attesting completeness is worse than one that stops. The
property is that loss is counted, health degrades when it occurs, and the
detector's conclusions track the health rather than the hope.

**Over time, does anything grow without bound?** A replay cache, a journal, a
queue, a set of file descriptors or a history list that grows forever is a
denial of service reachable by anyone who can make the agent work — and it
takes hours to appear, which is why it needs its own run.

Both report what they measured and let the caller decide. Neither invents a
pass.
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import resource
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

for _candidate in (os.environ.get("ANNULON_SRC"),
                   "/annulon/development/src", "/opt/sdnguard/src"):
    if _candidate and os.path.isdir(os.path.join(_candidate, "annulon")):
        sys.path.insert(0, _candidate)
        break
else:
    raise SystemExit("cannot locate the annulon package; set ANNULON_SRC")

from annulon.network.contract import NetworkOperation                   # noqa: E402
from annulon.network.liveness import (                                  # noqa: E402
    NetworkLivenessMonitor, network_collection_health,
)
from annulon.network.normalize import NetworkNormalizer                 # noqa: E402
from annulon.network.tracefs import TracefsNetworkSensor               # noqa: E402


def _rss_kb() -> int:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports kilobytes, macOS bytes.
    return usage if sys.platform.startswith("linux") else usage // 1024


def _open_fds() -> int:
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return -1


class Sink(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True)
        self._socket = socket.socket()
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(1024)
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


_BURST = r"""
import socket, sys
port, count = int(sys.argv[1]), int(sys.argv[2])
made = 0
for _ in range(count):
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect(("127.0.0.1", port)); made += 1
    except Exception:
        pass
    finally:
        s.close()
print(made)
"""


def _burst(port: int, count: int, workers: int) -> int:
    processes = [subprocess.Popen(
        [sys.executable, "-c", _BURST, str(port), str(count // workers)],
        stdout=subprocess.PIPE, text=True) for _ in range(workers)]
    total = 0
    for process in processes:
        out, _ = process.communicate(timeout=300)
        try:
            total += int(out.strip().splitlines()[-1])
        except (IndexError, ValueError):
            pass
    return total


def load(connections: int, workers: int, queue_limit: int) -> dict:
    """Drive real connections faster than the consumer drains them."""
    sink = Sink()
    sink.start()
    time.sleep(0.2)
    # A deliberately small buffer and queue: the point is to reach the limits
    # and observe the behaviour there, not to avoid them.
    sensor = TracefsNetworkSensor(buffer_kb=512, queue_limit=queue_limit)
    sensor.start()
    monitor = NetworkLivenessMonitor()
    normalizer = NetworkNormalizer()
    time.sleep(0.3)

    rss_before, fds_before = _rss_kb(), _open_fds()
    started = time.monotonic()
    made = _burst(sink.port, connections, workers)
    elapsed = time.monotonic() - started
    # Deliberately do NOT drain during the burst. A consumer that keeps up
    # cannot demonstrate what happens to one that does not.
    time.sleep(1.0)

    events = sensor.drain()
    observations = normalizer.normalize_all(events)
    attempts = [o for o in observations
                if o.operation is NetworkOperation.CONNECT_ATTEMPT
                and o.remote and o.remote.port == sink.port]
    loss = sensor.loss()
    health = sensor.health()
    combined = network_collection_health(health, monitor)
    rss_after, fds_after = _rss_kb(), _open_fds()
    sensor.stop()
    sensor.remove_instance()
    sink.stop()

    observed = len(attempts)
    return {
        "connections_requested": connections,
        "connections_made": made,
        "sink_accepted": sink.accepted,
        "elapsed_seconds": round(elapsed, 3),
        "connections_per_second": round(made / elapsed, 1) if elapsed else None,
        "attempts_observed": observed,
        "coverage": round(observed / made, 4) if made else None,
        "loss": loss.to_dict(),
        "queue_limit": queue_limit,
        "attests_completeness": health["attests_completeness"],
        "trustworthy_absence": combined.trustworthy_absence,
        "rss_kb_before": rss_before, "rss_kb_after": rss_after,
        "fds_before": fds_before, "fds_after": fds_after,
        # The security property, not the throughput: if anything was lost,
        # the sensor must say so rather than attesting completeness.
        "honest_under_load": (loss.lossless == health["attests_completeness"]),
        "loss_was_counted_when_coverage_dropped":
            (observed >= made) or (not loss.lossless) or (not combined.trustworthy_absence),
        "note": "not a throughput measurement and not a product target. The "
                "property is that loss is counted and health tracks it.",
    }


def soak(seconds: int, connections_per_cycle: int) -> dict:
    """Run a normal cycle repeatedly and watch for unbounded growth."""
    sink = Sink()
    sink.start()
    time.sleep(0.2)
    sensor = TracefsNetworkSensor(buffer_kb=4096)
    sensor.start()
    monitor = NetworkLivenessMonitor(deadline_seconds=3.0, history_limit=20)
    normalizer = NetworkNormalizer()
    time.sleep(0.3)

    samples = []
    cycles = 0
    started = time.monotonic()
    try:
        while time.monotonic() - started < seconds:
            _burst(sink.port, connections_per_cycle, 2)
            time.sleep(0.2)
            normalizer.normalize_all(sensor.drain())
            if cycles % 5 == 0:
                monitor.run(pump=lambda: normalizer.normalize_all(sensor.drain()),
                            loss=sensor.loss)
            cycles += 1
            gc.collect()
            samples.append({
                "t": round(time.monotonic() - started, 1),
                "rss_kb": _rss_kb(), "fds": _open_fds(),
                "queue_pending": sensor.pending,
                "liveness_history": len(monitor.history),
                "unparsed": sensor.health()["unparsed_lines"],
            })
    finally:
        sensor.stop()
        sensor.remove_instance()
        sink.stop()

    first, last = samples[0], samples[-1]
    midpoint = samples[len(samples) // 2]
    return {
        "duration_seconds": seconds, "cycles": cycles,
        "samples": samples[::max(1, len(samples) // 12)],
        "rss_kb_first": first["rss_kb"], "rss_kb_last": last["rss_kb"],
        "rss_growth_kb": last["rss_kb"] - first["rss_kb"],
        "fds_first": first["fds"], "fds_last": last["fds"],
        "fd_growth": last["fds"] - first["fds"],
        "liveness_history_bounded": last["liveness_history"] <= 20,
        "queue_drained_each_cycle": last["queue_pending"] == 0,
        # A leak shows as monotonic growth, so the midpoint matters: a single
        # early allocation is not a leak, and comparing only the endpoints
        # cannot tell the difference.
        "rss_growth_second_half_kb": last["rss_kb"] - midpoint["rss_kb"],
        "note": "a short soak. Hours-long runs remain NOT_RUN; this bounds "
                "the obvious leaks rather than proving their absence.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connections", type=int, default=4000)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--queue-limit", type=int, default=200)
    parser.add_argument("--soak-seconds", type=int, default=120)
    args = parser.parse_args()

    if not TracefsNetworkSensor.available():
        print(json.dumps({"completion": "EVIDENCE_INCOMPLETE",
                          "reason": "; ".join(
                              TracefsNetworkSensor.missing_requirements())}))
        return 1
    report = {
        "environment": {"kernel": os.uname().release,
                        "machine": os.uname().machine},
        "load": load(args.connections, args.workers, args.queue_limit),
        "soak": soak(args.soak_seconds, 200),
    }
    report["completion"] = (
        "COMPLETE" if report["load"]["honest_under_load"]
        and report["load"]["loss_was_counted_when_coverage_dropped"]
        and report["soak"]["liveness_history_bounded"]
        and report["soak"]["fd_growth"] <= 2
        else "EVIDENCE_INCOMPLETE")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["completion"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
