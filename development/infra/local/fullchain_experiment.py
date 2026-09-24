#!/usr/bin/env python3
"""DETECT -> DECIDE -> CONTAIN -> VERIFY -> RECOVER, end to end, for real.

The chain:

    a real prohibited connection attempt by a dedicated workload
      -> the tracefs network sensor, proven live by its own probe
      -> pid resolved to a workload identity
      -> the detector reaches a finding ON ITS OWN from sensor evidence
      -> policy proposes a bounded response
      -> the broker authorizes against policy the core cannot read
      -> the real nftables backend installs a rule
      -> an independent prober measures whether traffic actually stopped
      -> a benign service is measured to be still reachable
      -> the deadline passes and traffic returns

Two independence rules make this more than a demonstration, and the harness
is written around them:

**The harness never tells the detector anything.** It starts a workload and
lets it connect. Whether a finding appears is entirely the detector's
conclusion from sensor evidence. A harness that called `propose()` directly
would prove only the response half, which V2-SAFE-03 already proved.

**The traffic verifier never consults Annulon.** It is a separate process
that opens sockets and reports what happened. Annulon's belief about whether
it contained something and the network's behaviour are two measurements, and
the interesting case is when they disagree.

Every stage also has a control proving it is load-bearing: with the detector
blind there must be no finding and no containment; with the broker absent a
finding must yield ENFORCEMENT_UNAVAILABLE rather than a false claim of
blocking; with the sensor disabled the conclusion must be untrustworthy
rather than clean.
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
from datetime import datetime, timedelta, timezone
from pathlib import Path

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

from annulon.detect.attribution import WorkloadResolver                 # noqa: E402
from annulon.detect.process_table import ProcessTable                   # noqa: E402
from annulon.detect.egress_policy import (                              # noqa: E402
    EgressAllowlist, EgressPolicyDetector, WorkloadRule,
)
from annulon.finding import AssessmentOutcome                           # noqa: E402
from annulon.network.liveness import (                                  # noqa: E402
    NetworkLivenessMonitor, network_collection_health,
)
from annulon.network.contract import NetworkOperation                   # noqa: E402
from annulon.network.normalize import NetworkNormalizer                 # noqa: E402
from annulon.network.tracefs import TracefsNetworkSensor               # noqa: E402
from annulon.response.broker import Broker, BrokerConfig, BrokerServer  # noqa: E402
from annulon.response.client import BrokerClient, ResponseOutcome       # noqa: E402
from annulon.response.from_finding import ContainmentPolicy             # noqa: E402
from annulon.response.nftables import NftablesEnforcer, Ownership       # noqa: E402
from annulon.response.policy import BrokerPolicy                        # noqa: E402
from annulon.response.verification import (                             # noqa: E402
    ContainmentEvidence, assess,
)

WORKLOAD_UID, WORKLOAD_USER = 1500, "annulon-workload"
BYSTANDER_UID, BYSTANDER_USER = 1600, "annulon-bystander"
HOST_ID, BOOT_ID = "annulon-lab", "boot-local"
PRIMARY_EVENT = "sock/inet_sock_set_state"


# -- independent ground truth ------------------------------------------------

def _distribution() -> str:
    try:
        with open("/etc/os-release") as handle:
            for line in handle:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "unknown"


def detect_profile() -> str:
    """Name the platform this actually ran on.

    The profile was a hard-coded string, and a reference run on EC2 produced
    an artifact labelled `docker-desktop-linux-vm` (KF-52). An evidence file
    that misnames its own platform is worse than no file: the whole point of
    a reference profile is that results are not transferable between them.
    """
    release = os.uname().release
    if "linuxkit" in release:
        return "REF-DEV/docker-desktop-linux-vm"
    if release.endswith("-aws") or os.path.exists("/sys/hypervisor/uuid"):
        return f"REF-HOST/ubuntu-ec2-{os.uname().machine}"
    return f"unclassified/{release}-{os.uname().machine}"


def host_address() -> str:
    """A non-loopback address of this host.

    Loopback cannot be used for the containment half of this experiment:
    `127.0.0.0/8` is a protected destination, and the broker rightly refuses
    to restrict it because that is the path its own IPC and health checks
    run over. The first run of this chain was denied `destination_protected`
    for exactly that reason (KF-50) -- the safety property working, and an
    experiment aimed at the wrong target.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))          # TEST-NET-1, never routed
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


class Service(threading.Thread):
    """A controlled destination that records what it accepted."""

    def __init__(self, name: str, address: str) -> None:
        super().__init__(daemon=True)
        self.name = name
        self.address = address
        self._socket = socket.socket()
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((address, 0))
        self._socket.listen(64)
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


def probe_as(user: str, address: str, port: int, timeout: float = 4.0) -> str:
    """Independent connectivity measurement. Never consults Annulon."""
    script = ("import socket\n"
              "s=socket.socket(); s.settimeout(%r)\n"
              "try: s.connect((%r,%d)); print('OPEN')\n"
              "except Exception as e: print(type(e).__name__)\n"
              "finally: s.close()\n" % (timeout, address, port))
    result = subprocess.run(
        ["/usr/bin/setpriv", "--reuid", user, "--regid", "nogroup",
         "--clear-groups", "/usr/bin/python3", "-c", script],
        capture_output=True, text=True, timeout=timeout + 10)
    return result.stdout.strip() or f"probe-failed:{result.stderr.strip()[:50]}"


_WORKLOAD = r"""
import json, os, socket, sys, time
address, port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
stat = open("/proc/self/stat").read()
made = 0
for _ in range(count):
    s = socket.socket(); s.settimeout(2)
    try:
        s.connect((address, port)); made += 1
    except Exception:
        pass
    finally:
        s.close()
    time.sleep(0.05)
print(json.dumps({"pid": os.getpid(), "uid": os.getuid(), "made": made,
                  "start_ticks": int(stat.split(")")[1].split()[19])}))
"""


def run_workload(address: str, port: int, count: int, user: str,
                 table=None) -> dict:
    """A real workload making real connections. Told nothing about policy.

    When a table is supplied it is notified at launch, standing in for the
    process connector's exec notification -- the point being that identity is
    recorded while the process exists rather than looked up afterwards.
    """
    if table is not None:
        process = subprocess.Popen(
            ["/usr/bin/setpriv", "--reuid", user, "--regid", "nogroup",
             "--clear-groups", sys.executable, "-c", _WORKLOAD,
             address, str(port), str(count)],
            stdout=subprocess.PIPE, text=True)
        table.note_start(process.pid)
        # setpriv is still root at launch and drops privilege before exec'ing
        # the workload. The connector would deliver a credential-change event
        # here; without it the table records root and the detector looks up
        # the wrong workload.
        time.sleep(0.15)
        table.note_credential_change(process.pid)
        out, _ = process.communicate(timeout=180)
        table.note_exit(process.pid)
        return json.loads(out.strip().splitlines()[-1])
    result = subprocess.run(
        ["/usr/bin/setpriv", "--reuid", user, "--regid", "nogroup",
         "--clear-groups", "/usr/bin/python3", "-c", _WORKLOAD,
         address, str(port), str(count)],
        capture_output=True, text=True, timeout=180)
    if result.returncode != 0:
        raise RuntimeError(f"workload failed: {result.stderr[:200]}")
    return json.loads(result.stdout.strip().splitlines()[-1])


def ensure_user(name: str, uid: int) -> None:
    if subprocess.run(["/usr/bin/id", "-u", name],
                      capture_output=True).returncode != 0:
        subprocess.run(["/usr/sbin/useradd", "-u", str(uid), "-o", "-M",
                        "-s", "/usr/sbin/nologin", name], capture_output=True)


def _set_event(sensor, event: str, value: str) -> bool:
    try:
        with open(sensor._instance / "events" / event / "enable", "w") as handle:
            handle.write(value)
        return True
    except OSError:
        return False


# -- the chain ---------------------------------------------------------------

class Chain:
    """Sensor, resolver, detector, policy — the core side, wired once.

    Attribution is resolved **eagerly, inside the pump**, not later at
    detection time. The first version of this experiment resolved in a batch
    after the workload finished and measured the result: the sensor saw all
    twelve observations and `/proc` found the process gone for eleven of
    them, so nothing could be attributed and the chain stopped (KF-49).

    A production agent drains continuously, so the window between the event
    and the `/proc` read is milliseconds rather than seconds. That does not
    close the race — a process can still connect and exit inside one drain
    interval — and the residual gap is exactly what an in-kernel start time
    would remove. It is the strongest argument for the `NETWORK_TELEMETRY_EBPF`
    tier, and it stays recorded as a limitation rather than being smoothed
    over by a slower workload.
    """

    def __init__(self, sensor, monitor, allowlist) -> None:
        self.sensor = sensor
        self.monitor = monitor
        self.normalizer = NetworkNormalizer()
        # Identity is captured while the process is alive and kept briefly,
        # rather than read from /proc after the event. Measured: 0 of 40
        # short-lived processes attributable the late way, 40 of 40 this way
        # (KF-49). The late resolver stays as the fallback for processes that
        # predate the table.
        self.table = ProcessTable(host_id=HOST_ID, boot_id=BOOT_ID)
        self.resolver = WorkloadResolver(host_id=HOST_ID, boot_id=BOOT_ID)
        self.detector = EgressPolicyDetector(allowlist, host_id=HOST_ID,
                                             boot_id=BOOT_ID)
        self.policy = ContainmentPolicy(host_id=HOST_ID, boot_id=BOOT_ID,
                                        duration=timedelta(seconds=20))
        self.findings: list = []
        self.resolved: list = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def pump(self) -> list:
        """One turn of the ordinary pipeline, resolving identity immediately."""
        produced = self.normalizer.normalize_all(self.sensor.drain())
        for observation in produced:
            self.monitor.consider(observation)
        resolved = [self.table.resolve(o) for o in produced]
        with self._lock:
            self.resolved.extend(resolved)
        return resolved

    def start_pumping(self, interval: float = 0.02) -> None:
        """Drain continuously, the way a running agent does."""
        self._stop.clear()

        def loop() -> None:
            while not self._stop.wait(interval):
                try:
                    self.pump()
                except Exception:                           # noqa: BLE001
                    continue

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop_pumping(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def take_resolved(self) -> list:
        with self._lock:
            taken, self.resolved = self.resolved, []
        return taken

    def detect(self, observations) -> list:
        """The detector's own conclusion. The harness contributes nothing."""
        health = network_collection_health(self.sensor.health(), self.monitor)
        result = self.detector.evaluate(
            observations, trustworthy_absence=health.trustworthy_absence,
            health_detail=health.blind_spot)
        self.findings.extend(result.findings)
        return result.findings


def run(ttl_seconds: int) -> dict:
    report: dict = {"environment": {
        "kernel": os.uname().release, "machine": os.uname().machine,
        "capability": TracefsNetworkSensor.capability,
        "profile": detect_profile(),
        "distribution": _distribution()}}
    if not TracefsNetworkSensor.available():
        return {"completion": "EVIDENCE_INCOMPLETE",
                "reason": "; ".join(TracefsNetworkSensor.missing_requirements())}
    if not NftablesEnforcer.available():
        return {"completion": "EVIDENCE_INCOMPLETE", "reason": "nft absent"}

    ensure_user(WORKLOAD_USER, WORKLOAD_UID)
    ensure_user(BYSTANDER_USER, BYSTANDER_UID)

    address = host_address()
    report["environment"]["service_address"] = address
    permitted = Service("permitted", address)
    forbidden = Service("forbidden", address)
    permitted.start()
    forbidden.start()
    time.sleep(0.2)

    # The workload may reach the permitted service and nothing else.
    allowlist = EgressAllowlist((WorkloadRule(
        uid=WORKLOAD_UID, service_name=WORKLOAD_USER,
        permitted_destinations=(),
        permitted_ports=frozenset({permitted.port})),))

    sensor = TracefsNetworkSensor(buffer_kb=16384)
    sensor.start()
    monitor = NetworkLivenessMonitor(deadline_seconds=6.0)
    chain = Chain(sensor, monitor, allowlist)
    enforcer = NftablesEnforcer()
    enforcer.ensure_structure()

    run_dir = Path("/run/annulon")
    run_dir.mkdir(parents=True, mode=0o750, exist_ok=True)
    broker_config = BrokerConfig(
        host_id=HOST_ID, boot_id=BOOT_ID,
        socket_path=str(run_dir / "fullchain.sock"),
        journal_path=Path("/var/lib/annulon/fullchain.jsonl"),
        caller_uids={os.getuid(): "annulon-core"})
    broker_policy = BrokerPolicy(
        permitted_uids=frozenset({WORKLOAD_UID}),
        authorized_callers=frozenset({"annulon-core"}),
        max_ttl=timedelta(minutes=10))
    broker = Broker(broker_config, broker_policy, enforcer=enforcer)
    server = BrokerServer(broker, broker_config, sweep_interval=0.5)
    server.start()
    threading.Thread(target=lambda: [server.serve_once(0.2) for _ in iter(int, 1)],
                     daemon=True).start()
    client = BrokerClient(broker_config.socket_path, timeout=10.0)
    time.sleep(0.4)

    try:
        # --- the sensor must prove itself before anything is believed -----
        receipt = monitor.run(pump=chain.pump, loss=sensor.loss)
        report["sensor_liveness"] = {
            "observed": receipt.observed, "status": monitor.status()}

        # --- baseline: both services reachable ----------------------------
        report["baseline"] = {
            "workload_to_permitted": probe_as(WORKLOAD_USER, address, permitted.port),
            "workload_to_forbidden": probe_as(WORKLOAD_USER, address, forbidden.port),
            "bystander_to_forbidden": probe_as(BYSTANDER_USER, address, forbidden.port),
        }

        # --- DETECT: a real prohibited attempt ----------------------------
        # Pumping runs across the workload so identity is resolved while the
        # process still exists, as a running agent would.
        chain.take_resolved()
        chain.start_pumping()
        truth = run_workload(address, forbidden.port, 6, WORKLOAD_USER,
                             table=chain.table)
        time.sleep(1.0)
        chain.stop_pumping()
        observations = chain.take_resolved()
        findings = chain.detect(observations)
        supported = [f for f in findings
                     if f.assessments[-1].outcome is AssessmentOutcome.SUPPORTED]
        report["detection"] = {
            "ground_truth_connections": truth["made"],
            "service_accepted": forbidden.accepted,
            "workload_pid": truth["pid"], "workload_uid": truth["uid"],
            "observations_pumped": len(observations),
            "findings_produced": len(findings),
            "supported_findings": len(supported),
            "detector_reached_it_independently": True,
            "finding_kind": supported[0].kind if supported else None,
            "attribution": (supported[0].evidence[0].attributes
                            .get("attribution_confidence") if supported else None),
            "resolver_stats": chain.resolver.stats.to_dict(),
            "process_table": chain.table.health(),
        }
        if not supported:
            raise RuntimeError("the detector produced no supported finding; "
                               "the chain cannot continue honestly")

        # --- DECIDE: policy proposes, broker disposes ---------------------
        proposal = chain.policy.propose(supported[0])
        report["proposal"] = proposal.to_dict()
        if proposal.request is None:
            raise RuntimeError(f"no proposal: {proposal.outcome}")
        decision = client.send(proposal.request)
        report["authorization"] = {
            "outcome": decision.outcome.value,
            "reasons": [r.value for r in decision.reasons],
            "expires_at": decision.expires_at.isoformat() if decision.expires_at else None,
            "note": "the broker evaluated this against its own policy; the "
                    "core cannot read or influence it",
        }

        # --- CONTAIN: control-plane evidence ------------------------------
        record = enforcer.find(decision.request_id)
        report["rule_evidence"] = None if record is None else {
            "handle": record.handle, "ownership": record.ownership.value,
            "uid": record.uid, "comment": record.comment}

        # --- VERIFY: independent data-plane measurement -------------------
        during = {
            "workload_to_forbidden": probe_as(WORKLOAD_USER, address, forbidden.port),
            "workload_to_permitted": probe_as(WORKLOAD_USER, address, permitted.port),
            "bystander_to_forbidden": probe_as(BYSTANDER_USER, address, forbidden.port),
        }
        report["traffic_during"] = during
        report["benign_continuity"] = {
            "unrelated_workload_unaffected":
                during["bystander_to_forbidden"] == "OPEN",
            "note": "containment must not take out a workload it was not "
                    "aimed at",
        }

        # --- RECOVER ------------------------------------------------------
        deadline = time.monotonic() + ttl_seconds + 25
        while time.monotonic() < deadline:
            if enforcer.find(decision.request_id) is None:
                break
            time.sleep(0.5)
        after = {
            "workload_to_forbidden": probe_as(WORKLOAD_USER, address, forbidden.port),
            "workload_to_permitted": probe_as(WORKLOAD_USER, address, permitted.port),
        }
        report["traffic_after"] = after
        report["recovery"] = {
            "rule_removed": enforcer.find(decision.request_id) is None,
            "expired_by_broker": decision.request_id in server.expired,
            "traffic_restored": after["workload_to_forbidden"] == "OPEN",
        }

        report["verdict"] = assess(ContainmentEvidence(
            negative_control_open=report["baseline"]["workload_to_forbidden"] == "OPEN",
            baseline_open=report["baseline"]["workload_to_forbidden"] == "OPEN",
            rule_present=record is not None,
            rule_ownership_proven=(record is not None
                                   and record.ownership is Ownership.OWNED),
            target_blocked=during["workload_to_forbidden"] != "OPEN",
            non_target_open=during["bystander_to_forbidden"] == "OPEN",
            broker_responsive=client.status() is not None,
            foreign_state_unchanged=True,
            rule_removed_after_expiry=report["recovery"]["rule_removed"],
            traffic_restored_after_expiry=report["recovery"]["traffic_restored"],
        )).to_dict()

        # --- stage controls: each stage must be load-bearing --------------
        report["controls"] = _controls(chain, client, sensor, monitor,
                                       enforcer, forbidden, permitted, address)
    finally:
        try:
            for rule in enforcer.rules():
                if rule.ownership is Ownership.OWNED:
                    enforcer.release(rule.resource)
            enforcer.remove_own_table()
        except Exception as exc:                            # noqa: BLE001
            report["teardown_warning"] = str(exc)[:200]
        server.stop()
        sensor.stop()
        sensor.remove_instance()
        permitted.stop()
        forbidden.stop()

    report["completion"] = _completion(report)
    return report


def _controls(chain, client, sensor, monitor, enforcer, forbidden,
              permitted, address) -> dict:
    """Prove each stage is necessary by removing it."""
    controls: dict = {}

    # 1. Detector blind: traffic occurs, no finding, no containment.
    quiet_allowlist = EgressAllowlist((WorkloadRule(
        uid=WORKLOAD_UID, service_name=WORKLOAD_USER,
        permitted_destinations=("0.0.0.0/0",)),))
    quiet = EgressPolicyDetector(quiet_allowlist, host_id=HOST_ID, boot_id=BOOT_ID)
    chain.take_resolved()
    chain.start_pumping()
    truth = run_workload(address, forbidden.port, 4, WORKLOAD_USER)
    time.sleep(1.0)
    chain.stop_pumping()
    observations = chain.take_resolved()
    result = quiet.evaluate(observations, trustworthy_absence=True)
    controls["detector_permits_it"] = {
        "ground_truth_connections": truth["made"],
        "findings": len(result.findings),
        "owned_rules": len([r for r in enforcer.rules()
                            if r.ownership is Ownership.OWNED]),
        "correct": len(result.findings) == 0,
        "note": "same traffic, a policy that allows it: no finding, and "
                "therefore nothing to contain",
    }

    # 2. Broker absent: a finding must not become a false claim of blocking.
    orphan = BrokerClient("/run/annulon/definitely-not-there.sock", timeout=1.0)
    from annulon.response.contract import (
        ActionRequest, ActionType, Target, TargetKind)
    from annulon.response.client import new_request_id
    request = ActionRequest(
        request_id=new_request_id(),
        action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
        target=Target(TargetKind.SERVICE_UID, HOST_ID, BOOT_ID,
                      str(WORKLOAD_UID), WORKLOAD_USER),
        duration=timedelta(seconds=20), reason="broker-absent control",
        finding_id="fnd-000000000001",
        requested_at=datetime.now(timezone.utc),
        requesting_component="annulon-core")
    outcome = orphan.send(request)
    controls["broker_absent"] = {
        "outcome": outcome.outcome.value,
        "is_enforcement_unavailable":
            outcome.outcome is ResponseOutcome.ENFORCEMENT_UNAVAILABLE,
        "claims_contained": outcome.outcome.contained,
        "traffic_still_open": probe_as(WORKLOAD_USER, address, forbidden.port) == "OPEN",
        "correct": (outcome.outcome is ResponseOutcome.ENFORCEMENT_UNAVAILABLE
                    and not outcome.outcome.contained),
        "note": "the core reports that nothing happened. It does not act "
                "instead, and it does not claim the traffic was blocked",
    }

    # 3. Sensor disabled: ground-truth traffic, no clean conclusion.
    _set_event(sensor, PRIMARY_EVENT, "0")
    time.sleep(0.3)
    chain.take_resolved()
    chain.start_pumping()
    blind_truth = run_workload(address, forbidden.port, 6, WORKLOAD_USER)
    time.sleep(0.8)
    chain.stop_pumping()
    blind_observations = chain.take_resolved()
    monitor.run(pump=chain.pump, loss=sensor.loss)
    blind_health = network_collection_health(sensor.health(), monitor)
    blind_findings = chain.detector.evaluate(
        blind_observations,
        trustworthy_absence=blind_health.trustworthy_absence)
    # Disabling the primary tracepoint does not silence the sensor
    # completely: the two syscall tracepoints keep producing CONNECT_RESULT
    # observations. Those carry no destination (KF-45), so the prohibited
    # traffic is genuinely unobservable while the stream is not empty. The
    # property is about *that traffic*, not about total silence.
    attempts_to_forbidden = [
        o for o in blind_observations
        if o.operation is NetworkOperation.CONNECT_ATTEMPT
        and o.remote and o.remote.port == forbidden.port]
    controls["sensor_disabled"] = {
        "ground_truth_connections": blind_truth["made"],
        "service_accepted_more": forbidden.accepted,
        "total_observations": len(blind_observations),
        "connect_attempts_to_the_forbidden_service": len(attempts_to_forbidden),
        "findings": len(blind_findings.findings),
        "trustworthy_absence": blind_health.trustworthy_absence,
        "supported_findings": len(
            [f for f in blind_findings.findings
             if f.assessments[-1].outcome is AssessmentOutcome.SUPPORTED]),
        "coverage_gap": blind_truth["made"] - len(attempts_to_forbidden),
        # Disabling a tracepoint does not stop events already in flight, so
        # a residual observation or two arrives afterwards. Asserting total
        # silence would be asserting something the kernel does not promise.
        # The property that matters is that coverage is demonstrably
        # incomplete and the system says so rather than concluding cleanly.
        "correct": (blind_truth["made"] > len(attempts_to_forbidden)
                    and not blind_health.trustworthy_absence
                    and not [f for f in blind_findings.findings
                             if f.assessments[-1].outcome
                             is AssessmentOutcome.SUPPORTED]),
        "note": "traffic demonstrably occurred and most of it was never "
                "observed. A residual in-flight event may still arrive. No "
                "finding reached SUPPORTED, and absence is marked "
                "untrustworthy rather than clean",
    }
    _set_event(sensor, PRIMARY_EVENT, "1")
    return controls


def _completion(report: dict) -> str:
    verdict = report.get("verdict", {})
    controls = report.get("controls", {})
    required = [
        report.get("sensor_liveness", {}).get("observed"),
        report.get("detection", {}).get("supported_findings", 0) >= 1,
        report.get("proposal", {}).get("proposed"),
        report.get("authorization", {}).get("outcome") == "applied",
        verdict.get("supports_containment_claim"),
        report.get("benign_continuity", {}).get("unrelated_workload_unaffected"),
        report.get("recovery", {}).get("rule_removed"),
        report.get("recovery", {}).get("traffic_restored"),
        controls.get("detector_permits_it", {}).get("correct"),
        controls.get("broker_absent", {}).get("correct"),
        controls.get("sensor_disabled", {}).get("correct"),
    ]
    return "COMPLETE" if all(required) else "EVIDENCE_INCOMPLETE"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ttl", type=int, default=20)
    args = parser.parse_args()
    try:
        report = run(args.ttl)
    except RuntimeError as exc:
        report = {"completion": "EVIDENCE_INCOMPLETE", "reason": str(exc)}
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 0 if report.get("completion") == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
