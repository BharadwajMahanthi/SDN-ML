#!/usr/bin/env python3
"""Launch the sdnguard controller on the lab host.

Wires the real OS-Ken adapter to the security core and writes structured
evidence to disk. The security core is constructed here, in the launcher, so
that the adapter never decides anything about security configuration.

    python3 run_controller.py --evidence /opt/sdnguard/evidence/run-1 \
        [--observe-only] [--seconds 120]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.environ.get("SDNGUARD_SRC", "/opt/sdnguard/src"))

from sdnguard.clock import SystemClock                       # noqa: E402
from sdnguard.controller.app import SecurityController       # noqa: E402
from sdnguard.policy.engine import PolicyEngine, PolicyMode  # noqa: E402


class EvidenceWriter:
    """Append-only JSONL, flushed on every record so a kill -9 keeps evidence."""

    def __init__(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self.directory = directory
        self._handles: dict[str, object] = {}
        self._lock = threading.Lock()

    def write(self, stream: str, payload: dict) -> None:
        with self._lock:
            handle = self._handles.get(stream)
            if handle is None:
                handle = (self.directory / f"{stream}.jsonl").open("a")
                self._handles[stream] = handle
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def close(self) -> None:
        with self._lock:
            for handle in self._handles.values():
                handle.close()
            self._handles.clear()


class RecordingController(SecurityController):
    """SecurityController that journals every normalised event it receives.

    This is the join between a physical frame and a domain observation: each
    record carries the wall-clock moment and a monotonic sequence, so a packet
    seen on the wire can be matched to the event it produced.
    """

    def bind_evidence(self, writer: EvidenceWriter) -> None:
        self._evidence_writer = writer
        self._sequence = 0

    def _journal(self, kind: str, payload: dict) -> None:
        self._sequence += 1
        self._evidence_writer.write("controller_events", {
            "sequence": self._sequence,
            "kind": kind,
            "received_utc": datetime.now(timezone.utc).isoformat(),
            **payload,
        })

    def on_switch_connected(self, event):
        self._journal("switch_connected", {
            "dpid": str(event.dpid), "dpid_hex": event.dpid.hex,
            "generation": event.generation,
            "ports": [str(p) for p in event.ports]})
        super().on_switch_connected(event)

    def on_switch_disconnected(self, event):
        self._journal("switch_disconnected",
                      {"dpid": str(event.dpid), "generation": event.generation})
        super().on_switch_disconnected(event)

    def on_port_changed(self, event):
        self._journal("port_changed", {"port": str(event.port),
                                       "status": event.status.value,
                                       "generation": event.generation})
        super().on_port_changed(event)

    def on_host_observation(self, observation, generation):
        self._journal("host_observation", {
            "mac": str(observation.mac),
            "ip": str(observation.ip) if observation.ip else None,
            "port": str(observation.port),
            "source": observation.source,
            "broadcast": observation.is_broadcast,
            "observed_utc": observation.observed_at.isoformat(),
            "generation": generation})
        super().on_host_observation(observation, generation)

    def on_link_observed(self, event):
        self._journal("link_observed", {"receiving_port": str(event.receiving_port),
                                        "generation": event.generation})
        super().on_link_observed(event)

    def _record(self, finding):
        if finding is not None:
            self._evidence_writer.write("findings", finding.to_dict())
        super()._record(finding)
        if finding is not None:
            record = self.evidence.get(finding.finding_id)
            if record and record.decision:
                self._evidence_writer.write("decisions", {
                    "finding_id": finding.finding_id,
                    "action": record.decision.action.value,
                    "scope": str(record.decision.scope) if record.decision.scope else None,
                    "reason": record.decision.reason,
                    "enforcing": record.decision.is_enforcing,
                    "decided_utc": record.decision.decided_at.isoformat()})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", default="/opt/sdnguard/evidence/current")
    parser.add_argument("--seconds", type=int, default=0, help="0 = run until signalled")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--detection-disabled", action="store_true",
                        help="negative control: normalise events but emit no findings")
    parser.add_argument("--ofp-port", type=int, default=6653)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    from os_ken.base.app_manager import AppManager      # noqa: E402
    from os_ken import cfg                              # noqa: E402

    from sdnguard.adapter.osken import OsKenAdapter     # noqa: E402

    cfg.CONF(["--ofp-tcp-listen-port", str(args.ofp_port)],
             project="os_ken", default_config_files=[])

    writer = EvidenceWriter(Path(args.evidence))
    mode = PolicyMode.ENFORCE if args.enforce else PolicyMode.OBSERVE
    policy = PolicyEngine(mode=mode, rules=PolicyEngine.default_rules())

    manager = AppManager.get_instance()
    manager.load_apps(["sdnguard.adapter.osken"])
    contexts = manager.create_contexts()
    services = manager.instantiate_apps(**contexts)
    adapter = manager.applications["OsKenAdapter"]

    controller = RecordingController(commands=adapter, clock=SystemClock(),
                                     policy=policy)
    controller.bind_evidence(writer)
    if args.detection_disabled:
        # Negative control: the pipeline runs and events are journalled, but no
        # finding is ever produced. Implemented by neutering the recording
        # method, so the difference from a normal run is exactly one thing.
        controller._record = lambda finding: None
    adapter.attach(controller)

    writer.write("controller_events", {
        "sequence": 0, "kind": "controller_started",
        "received_utc": datetime.now(timezone.utc).isoformat(),
        "mode": mode.value, "detection_disabled": args.detection_disabled,
        "openflow_listen_port": args.ofp_port})

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    # KF-21: do NOT spawn OpenFlowController here. AppManager.instantiate_apps()
    # starts os_ken's OFPHandler, whose start() already spawns the listener.
    # Spawning a second one races for port 6653 and the loser raises inside an
    # eventlet timer -- noisy, and it would mask a real bind failure.
    import eventlet                                      # noqa: E402

    def ticker() -> None:
        while not stop.is_set():
            controller.tick()
            eventlet.sleep(0.5)
    tick_thread = eventlet.spawn(ticker)

    deadline = time.monotonic() + args.seconds if args.seconds else None
    try:
        while not stop.is_set():
            if deadline and time.monotonic() >= deadline:
                break
            eventlet.sleep(0.5)
    finally:
        stop.set()
        tick_thread.kill()
        health = controller.health()
        writer.write("controller_events", {
            "sequence": -1, "kind": "controller_stopped",
            "received_utc": datetime.now(timezone.utc).isoformat(),
            "health": health})
        (Path(args.evidence) / "health.json").write_text(
            json.dumps(health, indent=2, sort_keys=True) + "\n")
        writer.close()
        print(json.dumps(health, indent=2, sort_keys=True))
        sys.stdout.flush()
        # KF-22: returning from main() does NOT end the process. os_ken's
        # AppManager leaves greenthreads and a hub running, so the interpreter
        # stays alive, keeps port 6653 bound, and the next experiment's
        # controller silently fails to bind -- producing a run whose emptiness
        # could be misread as a negative result. Close the apps, then leave
        # unconditionally.
        try:
            manager.close()
        except Exception:
            LOG_EXIT = True
        os._exit(0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
