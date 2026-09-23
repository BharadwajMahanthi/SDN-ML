"""The unprivileged core as a runnable service.

Wiring only, and deliberately powerless: this process holds no capability to
change the host. It observes, attributes, detects, proposes, and reports
what the broker decided. If the broker is absent it says
`ENFORCEMENT_UNAVAILABLE` and carries on observing.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from datetime import timedelta
from pathlib import Path

from annulon.detect.attribution import WorkloadResolver
from annulon.detect.egress_policy import (
    EgressAllowlist, EgressPolicyDetector, WorkloadRule,
)
from annulon.finding import AssessmentOutcome
from annulon.network.liveness import (
    NetworkLivenessMonitor, network_collection_health,
)
from annulon.network.normalize import NetworkNormalizer
from annulon.network.tracefs import TracefsNetworkSensor, TracefsUnavailable
from annulon.response.client import BrokerClient
from annulon.response.from_finding import ContainmentPolicy

__all__ = ["main", "Agent"]

DEFAULT_CONFIG = Path("/etc/annulon/agent.json")


class Agent:
    """Sensor, resolver, detector, proposal — one turn at a time."""

    def __init__(self, config: dict) -> None:
        self.host_id = str(config.get("host_id") or os.uname().nodename)
        self.boot_id = str(config.get("boot_id") or "unknown-boot")
        self.sensor = TracefsNetworkSensor(
            buffer_kb=int(config.get("buffer_kb", 4096)))
        self.monitor = NetworkLivenessMonitor()
        self.normalizer = NetworkNormalizer()
        self.resolver = WorkloadResolver(host_id=self.host_id,
                                         boot_id=self.boot_id)
        self.detector = EgressPolicyDetector(
            _allowlist(config), host_id=self.host_id, boot_id=self.boot_id)
        self.policy = ContainmentPolicy(
            host_id=self.host_id, boot_id=self.boot_id,
            duration=timedelta(seconds=int(config.get("containment_seconds", 300))))
        self.client = BrokerClient(
            str(config.get("broker_socket") or "/run/annulon/broker.sock"))
        self.propose = bool(config.get("propose_containment", False))

    def turn(self) -> dict:
        """Drain, attribute, detect, and optionally propose. Returns a report."""
        observations = [self.resolver.resolve(o) for o
                        in self.normalizer.normalize_all(self.sensor.drain())]
        for observation in observations:
            self.monitor.consider(observation)
        health = network_collection_health(self.sensor.health(), self.monitor)
        result = self.detector.evaluate(
            observations, trustworthy_absence=health.trustworthy_absence,
            health_detail=health.blind_spot)

        outcomes = []
        for finding in result.findings:
            if finding.assessments[-1].outcome is not AssessmentOutcome.SUPPORTED:
                continue
            if not self.propose:
                outcomes.append({"finding": finding.finding_id,
                                 "action": "observe_only"})
                continue
            proposal = self.policy.propose(finding)
            if proposal.request is None:
                outcomes.append({"finding": finding.finding_id,
                                 "action": proposal.outcome})
                continue
            decision = self.client.send(proposal.request)
            outcomes.append({"finding": finding.finding_id,
                             "action": decision.outcome.value,
                             "reasons": [r.value for r in decision.reasons]})
        return {"observations": len(observations),
                "findings": len(result.findings),
                "trustworthy_absence": health.trustworthy_absence,
                "outcomes": outcomes}


def _allowlist(config: dict) -> EgressAllowlist:
    rules = []
    for entry in config.get("workloads") or []:
        rules.append(WorkloadRule(
            uid=int(entry["uid"]), service_name=str(entry.get("service", "")),
            permitted_destinations=tuple(entry.get("permitted_destinations", [])),
            permitted_ports=frozenset(int(p) for p in entry.get("permitted_ports", []))))
    return EgressAllowlist(tuple(rules))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="annulon-agent", description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--check", action="store_true",
                        help="report capability and exit without observing")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args(argv)

    try:
        config = json.loads(args.config.read_text()) if args.config.exists() else {}
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"agent configuration unreadable: {exc}")

    if args.check:
        print(json.dumps({
            "sensor_available": TracefsNetworkSensor.available(),
            "missing": list(TracefsNetworkSensor.missing_requirements()),
            "capability": TracefsNetworkSensor.capability}, indent=2))
        return 0

    agent = Agent(config)
    try:
        agent.sensor.start()
    except TracefsUnavailable as exc:
        # Refuse to run blind while claiming to watch.
        raise SystemExit(f"network sensor unavailable: {exc}")

    stopping = {"now": False}

    def _stop(_signum, _frame) -> None:
        stopping["now"] = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        while not stopping["now"]:
            print(json.dumps(agent.turn(), sort_keys=True), flush=True)
            if args.once:
                break
            time.sleep(args.interval)
    finally:
        agent.sensor.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
