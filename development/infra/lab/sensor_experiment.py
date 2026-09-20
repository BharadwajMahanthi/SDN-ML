#!/usr/bin/env python3
"""V2-HOST-01: measure candidate Linux sensors against real process activity.

The experiment is designed so a candidate can *fail*. Ground truth is produced
by the launcher, which records every PID it actually created, and each sensor
independently records what it observed. The two are compared afterwards; no
sensor is told what the answer is.

The decisive workload is short-lived processes, because that is where the
obvious approach breaks and where real attacker activity lives -- a
`curl | sh` exists for milliseconds.

    python3 sensor_experiment.py --sensor proc_connector --count 500 --evidence DIR
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.environ.get("ANNULON_SRC", "/opt/sdnguard/src"))

from annulon.collectors.base import SensorUnavailable          # noqa: E402
from annulon.collectors.proc_connector import ProcConnectorSensor  # noqa: E402
from annulon.collectors.proc_poll import ProcPollSensor        # noqa: E402
from annulon.completion import (                                # noqa: E402
    ExitReason,
    ExperimentRecorder,
)

SENSORS = {
    "proc_connector": lambda: ProcConnectorSensor(),
    "proc_poll_100ms": lambda: ProcPollSensor(interval=0.1),
    "proc_poll_10ms": lambda: ProcPollSensor(interval=0.01),
}


def launch_workload(count: int, sleep_ms: int, out: Path) -> dict:
    """Ground truth: spawn processes and record exactly which PIDs existed.

    Written only by the harness. The sensors never see this file.
    """
    pids: list[int] = []
    started = datetime.now(timezone.utc)
    begin = time.monotonic()
    for index in range(count):
        if sleep_ms:
            proc = subprocess.Popen(["/bin/sleep", f"{sleep_ms / 1000:.3f}"])
        else:
            # The hostile case: exits almost immediately.
            proc = subprocess.Popen(["/bin/true"])
        pids.append(proc.pid)
        proc.wait()
    elapsed = time.monotonic() - begin
    truth = {
        "scenario": "process_launch",
        "count": count,
        "sleep_ms": sleep_ms,
        "started_utc": started.isoformat(),
        "ended_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 4),
        "launched_pids": pids,
    }
    out.write_text(json.dumps(truth, indent=2))
    return truth


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sensor", required=True, choices=sorted(SENSORS))
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--sleep-ms", type=int, default=0)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--settle", type=float, default=2.0)
    args = parser.parse_args()

    evidence = Path(args.evidence)
    run_id = f"{args.sensor}-{args.count}x{args.sleep_ms}ms"
    recorder = ExperimentRecorder(evidence, run_id, "sensor_evaluation")
    recorder.declare_producer("ground_truth")
    recorder.declare_producer("observed")
    recorder.starting()

    sensor = SENSORS[args.sensor]()
    ok, detail = sensor.preflight()
    if not ok:
        recorder.abort(f"sensor unavailable: {detail}")
        recorder.finalize(ExitReason.ERROR)
        print(json.dumps({"sensor": args.sensor, "available": False,
                          "detail": detail}))
        return 2
    try:
        sensor.start()
    except SensorUnavailable as exc:
        recorder.abort(str(exc))
        recorder.finalize(ExitReason.ERROR)
        print(json.dumps({"sensor": args.sensor, "available": False,
                          "detail": str(exc)}))
        return 2
    recorder.ready()

    observed: list[dict] = []
    stop = threading.Event()
    latencies: list[float] = []

    def collect() -> None:
        while not stop.is_set():
            for event in sensor.events(timeout=0.2):
                observed.append({
                    "event_type": event.event_type,
                    "pid": event.attributes.get("pid"),
                    "sequence": event.sequence,
                    "received": event.received_time.isoformat(),
                })

    worker = threading.Thread(target=collect, daemon=True)
    worker.start()
    time.sleep(0.5)                      # let the collector settle

    recorder.scenario_started()
    truth = launch_workload(args.count, args.sleep_ms,
                            evidence / "ground_truth.json")
    recorder.producer_finalized("ground_truth")

    time.sleep(args.settle)              # allow in-flight events to arrive
    stop.set()
    worker.join(timeout=5)
    sensor.stop()
    recorder.scenario_completed()

    launched = set(truth["launched_pids"])
    exec_pids = {e["pid"] for e in observed
                 if e["event_type"] == "host.process.exec" and e["pid"]}
    seen_any = {e["pid"] for e in observed if e["pid"]}
    matched = launched & seen_any
    health = sensor.health()

    result = {
        "sensor": args.sensor,
        "available": True,
        "requires_root": sensor.requires_root(),
        "capabilities": sorted(c.value for c in sensor.capabilities()),
        "launched": len(launched),
        "observed_events": len(observed),
        "matched_pids": len(matched),
        "detection_rate": round(len(matched) / max(1, len(launched)), 4),
        "missed": len(launched - seen_any),
        "workload_elapsed_seconds": truth["elapsed_seconds"],
        "sensor_health": {
            "running": health.running, "lossy": health.lossy,
            **health.stats.as_dict()},
    }
    (evidence / "observed.json").write_text(json.dumps(
        {"result": result, "events": observed[:2000]}, indent=2))
    recorder.producer_finalized("observed")
    manifest = recorder.finalize(
        ExitReason.NORMAL, artifacts=("ground_truth.json", "observed.json"))
    result["completion_status"] = manifest.status.value
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
