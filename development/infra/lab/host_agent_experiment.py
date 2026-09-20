#!/usr/bin/env python3
"""V2-HOST-02 crossover: a real process becomes Annulon evidence.

    real process execs
      -> netlink proc connector (kernel push)
      -> /proc enrichment of a PID we already have
      -> Annulon common event
      -> Evidence -> Finding -> Assessment

Ground truth is written only by the launcher and names the marker binary it
created. The agent is never told what to look for. The comparison happens
afterwards, in the evaluator.

    python3 host_agent_experiment.py --evidence DIR [--sensor-disabled]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.environ.get("ANNULON_SRC", "/opt/sdnguard/src"))

from annulon.agent.host_agent import AgentConfig, HostAgent        # noqa: E402
from annulon.collectors.proc_connector import ProcConnectorSensor  # noqa: E402
from annulon.completion import ExitReason, ExperimentRecorder      # noqa: E402
from annulon.evidence import (                                     # noqa: E402
    Evidence,
    EvidenceGraph,
    EvidenceKind,
    MissingEvidence,
    MissingReason,
    Stance,
)
from annulon.finding import (                                      # noqa: E402
    Assessment,
    AssessmentOutcome,
    CollectionHealth,
    Confidence,
    ConfidenceBasis,
    Finding,
    Severity,
    summarize_evidence,
)

MARKER = "/tmp/annulon-marker-binary"


def install_marker() -> None:
    """A uniquely named executable, so attribution is unambiguous."""
    Path(MARKER).write_text("#!/bin/sh\nexit 0\n")
    os.chmod(MARKER, 0o755)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--count", type=int, default=25)
    parser.add_argument("--sensor-disabled", action="store_true",
                        help="negative control: run the scenario with no sensor")
    args = parser.parse_args()

    evidence_dir = Path(args.evidence)
    run_id = "host-crossover" + ("-negative" if args.sensor_disabled else "")
    recorder = ExperimentRecorder(evidence_dir, run_id, "host_process_attribution")
    recorder.declare_producer("ground_truth")
    recorder.declare_producer("events")
    recorder.declare_producer("findings")
    recorder.starting()

    install_marker()
    agent = None
    if not args.sensor_disabled:
        sensor = ProcConnectorSensor()
        ok, detail = sensor.preflight()
        if not ok:
            recorder.abort(f"sensor unavailable: {detail}")
            recorder.finalize(ExitReason.ERROR)
            print(json.dumps({"error": detail}))
            return 2
        agent = HostAgent(sensor, config=AgentConfig(enrich=True,
                                                     capture_argv=True,
                                                     queue_size=8192))
        agent.start()
        time.sleep(0.5)
    recorder.ready()

    # -- ground truth, written only here --------------------------------
    recorder.scenario_started()
    started = datetime.now(timezone.utc)
    launched = []
    for _ in range(args.count):
        proc = subprocess.Popen([MARKER])
        launched.append(proc.pid)
        proc.wait()
    truth = {
        "scenario": "marker_binary_execution",
        "marker_path": MARKER,
        "count": args.count,
        "launched_pids": launched,
        "started_utc": started.isoformat(),
        "ended_utc": datetime.now(timezone.utc).isoformat(),
        "sensor_disabled": args.sensor_disabled,
    }
    (evidence_dir / "ground_truth.json").write_text(json.dumps(truth, indent=2))
    recorder.producer_finalized("ground_truth")
    time.sleep(2.0)
    recorder.scenario_completed()

    # -- detector side, entirely independent -----------------------------
    events = agent.drain(limit=20000) if agent else []
    marker_events = [e for e in events
                     if e.attributes.get("exe") == MARKER
                     or e.attributes.get("comm") == Path(MARKER).name[:15]]
    (evidence_dir / "events.jsonl").write_text(
        "".join(json.dumps(e.to_dict(), sort_keys=True) + "\n"
                for e in marker_events[:500]))
    recorder.producer_finalized("events")

    findings = []
    graph = EvidenceGraph()
    for index, event in enumerate(marker_events[:5], start=1):
        pid = event.attributes.get("pid")
        finding = Finding(f"FN-HOST-{index:04d}", "host.marker_binary_executed",
                          entity_refs=event.entity_refs, created_at=event.observed_time)
        item = Evidence(
            evidence_id=f"FN-HOST-{index:04d}-EV-EXEC",
            kind=EvidenceKind.DIRECT_OBSERVATION, stance=Stance.SUPPORTS,
            origin_group="host-proc-connector",
            summary=f"process {pid} executed {event.attributes.get('exe')}",
            observed_at=event.observed_time, produced_at=event.received_time,
            source_event_ids=(event.event_id,),
            attributes={"pid": pid, "uid": event.attributes.get("uid")})
        graph.add(item)
        finding.attach(item)
        if "enrichment_missing" in event.attributes:
            finding.note_missing(MissingEvidence(
                "process detail", MissingReason.NOT_YET_ARRIVED,
                "host-proc-enrichment",
                "process exited before /proc could be read"))
        summary = summarize_evidence(finding.evidence, finding.missing, graph)
        finding.assess(Assessment(
            f"FN-HOST-{index:04d}-AS-0001", AssessmentOutcome.SUPPORTED,
            Severity.LOW, Confidence.STRONG, ConfidenceBasis.DIRECT_OBSERVATION,
            CollectionHealth.HEALTHY if agent and agent.trustworthy_absence()
            else CollectionHealth.DEGRADED,
            "the kernel reported this execution directly",
            event.observed_time, summary))
        findings.append(finding)

    (evidence_dir / "findings.jsonl").write_text(
        "".join(f.to_json() + "\n" for f in findings))
    recorder.producer_finalized("findings")

    # Health must be read while the agent is running: reading it after stop()
    # reports a stopped sensor and makes absence look untrustworthy for the
    # wrong reason.
    if agent:
        manifest_payload = agent.manifest().to_dict()
        live_absence = agent.trustworthy_absence()
        live_collection = agent.collection_complete()
        live_stats = agent.stats.as_dict()
    else:
        manifest_payload = {"state": "degraded_collection",
                            "note": "sensor disabled (negative control)"}
        live_absence = live_collection = False
        live_stats = {}
    (evidence_dir / "capability_manifest.json").write_text(
        json.dumps(manifest_payload, indent=2))
    if agent:
        agent.stop()

    completion = recorder.finalize(ExitReason.NORMAL, artifacts=(
        "ground_truth.json", "events.jsonl", "findings.jsonl"))

    result = {
        "sensor_disabled": args.sensor_disabled,
        "launched": len(launched),
        "marker_events_observed": len(marker_events),
        "findings_produced": len(findings),
        "agent_state": manifest_payload.get("state"),
        "trustworthy_absence": live_absence,
        "collection_complete": live_collection,
        "agent_stats": live_stats,
        "completion_status": completion.status.value,
    }
    (evidence_dir / "result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
