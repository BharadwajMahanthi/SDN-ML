#!/usr/bin/env python3
"""Network liveness against a real kernel, including the ways it should fail.

The claim being tested is narrow and worth stating exactly: Annulon can
demonstrate that the selected tracefs observation path is *currently* able to
observe a kernel network event, and refuses to treat silence as meaningful
when it cannot. It says nothing about external connectivity.

Independent truth is kept separate throughout. Whether the probe connection
actually happened is established by the probe's own listener accepting it —
a fact about sockets — and is compared afterwards with whether Annulon
observed it, which is a fact about telemetry. The dangerous confusion is
between those two, so they are never derived from each other.

Cases, in the order they run:

1. positive control      — probe fires, is observed, liveness HEALTHY
2. tracepoint disabled   — thread alive, fd open, probe must FAIL
3. false silence         — real traffic while blind: degraded, never clean
4. recovery              — a later clean probe, with the gap still on record
5. cancellation          — a pending probe abandoned promptly
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

from annulon.network.liveness import (                                  # noqa: E402
    NetworkLivenessMonitor, network_collection_health,
)
from annulon.network.normalize import NetworkNormalizer                 # noqa: E402
from annulon.network.tracefs import (                                   # noqa: E402
    REQUIRED_EVENTS, TracefsNetworkSensor,
)

PRIMARY_EVENT = "sock/inet_sock_set_state"


class Pipeline:
    """The ordinary consumer path: drain, normalise, hand on.

    The liveness monitor is offered each observation *after* the bounded
    queue and the normaliser, so a broken or saturated userspace path cannot
    be reported healthy because tracefs parsing still works. Nothing is
    consumed on the monitor's behalf.
    """

    def __init__(self, sensor: TracefsNetworkSensor,
                 monitor: NetworkLivenessMonitor) -> None:
        self.sensor = sensor
        self.normalizer = NetworkNormalizer()
        self.monitor = monitor
        self.delivered: list = []
        self.internal: list = []

    def pump(self) -> list:
        produced = self.normalizer.normalize_all(self.sensor.drain())
        for observation in produced:
            self.monitor.consider(observation)
            if self.monitor.is_internal(observation):
                self.internal.append(observation)
            else:
                self.delivered.append(observation)
        return produced


def _traffic(port: int, count: int = 30) -> int:
    """Ground truth traffic, independent of Annulon."""
    script = (
        "import socket,sys\n"
        "made=0\n"
        "for _ in range(%d):\n"
        "    s=socket.socket(); s.settimeout(1)\n"
        "    try: s.connect(('127.0.0.1',%d)); made+=1\n"
        "    except Exception: pass\n"
        "    finally: s.close()\n"
        "print(made)\n" % (count, port))
    result = subprocess.run([sys.executable, "-c", script],
                            capture_output=True, text=True, timeout=60)
    return int(result.stdout.strip() or 0)


class Listener(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True)
        self._socket = socket.socket()
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(128)
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


def _set_event(sensor: TracefsNetworkSensor, event: str, value: str) -> bool:
    path = sensor._instance / "events" / event / "enable"
    try:
        with open(path, "w") as handle:
            handle.write(value)
        return True
    except OSError:
        return False


def run() -> dict:
    report: dict = {"environment": {
        "kernel": os.uname().release, "machine": os.uname().machine,
        "capability": TracefsNetworkSensor.capability,
        "sensor_pid": os.getpid()}}

    if not TracefsNetworkSensor.available():
        return {"completion": "EVIDENCE_INCOMPLETE",
                "reason": "; ".join(TracefsNetworkSensor.missing_requirements())}

    sensor = TracefsNetworkSensor(buffer_kb=8192)
    sensor.start()
    monitor = NetworkLivenessMonitor(deadline_seconds=6.0)
    pipeline = Pipeline(sensor, monitor)
    time.sleep(0.3)

    try:
        # --- 1. positive control -----------------------------------------
        before_delivered = len(pipeline.delivered)
        receipt = monitor.run(pump=pipeline.pump, loss=sensor.loss)
        health = network_collection_health(sensor.health(), monitor)
        report["positive_control"] = {
            "connection_actually_opened": receipt.connection_made,
            "annulon_observed_it": receipt.observed,
            "latency_seconds": receipt.result.latency_seconds,
            "loss_delta": receipt.loss_delta,
            "liveness_status": monitor.status(),
            "trustworthy_absence": health.trustworthy_absence,
            "probe_marked_internal": len(pipeline.internal) > 0,
            "unrelated_observations_still_delivered":
                len(pipeline.delivered) >= before_delivered,
            "note": "the connection is established independently by the "
                    "probe's own listener; whether Annulon saw it is a "
                    "separate fact and the two are compared, never derived "
                    "from one another",
        }

        # --- 2. the selected tracepoint disabled, thread still alive ------
        disabled = _set_event(sensor, PRIMARY_EVENT, "0")
        time.sleep(0.3)
        blind_receipt = monitor.run(pump=pipeline.pump, loss=sensor.loss)
        blind_health = network_collection_health(sensor.health(), monitor)
        report["primary_tracepoint_disabled"] = {
            "disabled": disabled,
            "reader_thread_still_alive": sensor.health()["running"],
            "connection_actually_opened": blind_receipt.connection_made,
            "annulon_observed_it": blind_receipt.observed,
            "liveness_status": monitor.status(),
            "trustworthy_absence": blind_health.trustworthy_absence,
            "blind_spot": blind_health.blind_spot,
            "note": "the thread is alive, the descriptor is open, and the "
                    "sensor can see nothing. This is the case a liveness "
                    "check based on thread state would have called healthy.",
        }

        # --- 3. false silence: real traffic while blind -------------------
        listener = Listener()
        listener.start()
        time.sleep(0.2)
        made = _traffic(listener.port, 30)
        time.sleep(0.8)
        pipeline.pump()
        to_listener = [o for o in pipeline.delivered
                       if o.remote and o.remote.port == listener.port]
        silent_health = network_collection_health(sensor.health(), monitor)
        listener.stop()
        report["false_silence"] = {
            "ground_truth_connections_made": made,
            "ground_truth_server_accepted": listener.accepted,
            "annulon_observations_of_that_traffic": len(to_listener),
            "liveness_status": monitor.status(),
            "trustworthy_absence": silent_health.trustworthy_absence,
            "attests_completeness": silent_health.attests_completeness,
            "correct": (made > 0 and listener.accepted > 0
                        and len(to_listener) == 0
                        and not silent_health.trustworthy_absence),
            "note": "traffic demonstrably occurred and Annulon observed none "
                    "of it. Silence must not read as a clean result.",
        }

        # --- 4. recovery is prospective -----------------------------------
        _set_event(sensor, PRIMARY_EVENT, "1")
        time.sleep(0.3)
        recovery = monitor.run(pump=pipeline.pump, loss=sensor.loss)
        recovered_health = network_collection_health(sensor.health(), monitor)
        failures_on_record = [r for r in monitor.history if not r.observed]
        report["recovery"] = {
            "annulon_observed_it": recovery.observed,
            "liveness_status": monitor.status(),
            "trustworthy_absence_now": recovered_health.trustworthy_absence,
            "earlier_failures_still_on_record": len(failures_on_record),
            "correct": (recovery.observed and len(failures_on_record) >= 1),
            "note": "a later clean probe says the path works now. It does "
                    "not say anything about the interval that failed, and "
                    "the record keeps both.",
        }

        # --- 5. cancellation is prompt ------------------------------------
        cancel = threading.Event()
        cancel.set()
        started = time.monotonic()
        cancelled = monitor.run(pump=pipeline.pump, loss=sensor.loss,
                                cancel=cancel)
        elapsed = time.monotonic() - started
        report["cancellation"] = {
            "elapsed_seconds": round(elapsed, 3),
            "bounded": elapsed < 5.0,
            "observed": cancelled.observed,
        }

        # --- shutdown must stay bounded (KF-44) ---------------------------
        stop_started = time.monotonic()
        sensor.stop()
        stop_elapsed = time.monotonic() - stop_started
        report["shutdown"] = {
            "elapsed_seconds": round(stop_elapsed, 3),
            "bounded": stop_elapsed < 10.0,
            "note": "KF-44: a blocking buffered read made close() hang "
                    "forever. This must stay bounded.",
        }
    finally:
        try:
            sensor.stop()
        except Exception:                                   # noqa: BLE001
            pass
        sensor.remove_instance()

    report["verdict"] = _verdict(report)
    return report


def _verdict(report: dict) -> dict:
    positive = report["positive_control"]
    disabled = report["primary_tracepoint_disabled"]
    silence = report["false_silence"]
    recovery = report["recovery"]
    checks = {
        "probe_connection_really_happened": positive["connection_actually_opened"],
        "probe_was_observed": positive["annulon_observed_it"],
        "healthy_only_after_a_real_probe": positive["liveness_status"] == "HEALTHY",
        "clean_probe_allows_trustworthy_absence": positive["trustworthy_absence"],
        "probe_recognised_as_internal": positive["probe_marked_internal"],
        "disabled_tracepoint_fails_liveness":
            disabled["liveness_status"] == "FAILED",
        "thread_alive_while_blind": disabled["reader_thread_still_alive"],
        "blind_sensor_is_not_trustworthy": not disabled["trustworthy_absence"],
        "false_silence_handled": silence["correct"],
        "recovery_is_prospective": recovery["correct"],
        "cancellation_bounded": report["cancellation"]["bounded"],
        "shutdown_bounded": report["shutdown"]["bounded"],
    }
    checks["completion"] = ("COMPLETE" if all(v for k, v in checks.items())
                            else "EVIDENCE_INCOMPLETE")
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    report = run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("verdict", {}).get("completion") == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
