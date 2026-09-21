#!/usr/bin/env python3
"""Measure candidate network sensors against one independent ground truth.

Nothing here selects a mechanism because it is simple or popular. Each
candidate observes the *same* burst of real connections on the *same* kernel,
and each is scored against a ground truth neither of them produces: a
controlled TCP server that independently records every connection it
accepted, plus the harness's own record of which process made them.

The comparison that matters is short-lived activity. `/proc` polling already
failed that test for process lifecycle — 500 of 500 short-lived execs missed
while reporting no loss — and there is no reason to assume network polling
behaves differently just because it is easier to implement.

Candidates:
  B  eBPF via tracepoints (sys_enter_connect / sys_exit_connect)
  D  /proc/net/tcp snapshot polling, the obvious baseline
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field

TRACEFS = "/sys/kernel/tracing"
#: /proc/net/tcp state column, hex.
_TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
               "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
               "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
               "0A": "LISTEN", "0B": "CLOSING"}


def mount_tracefs() -> None:
    if not os.path.isdir(f"{TRACEFS}/events"):
        subprocess.run(["mount", "-t", "tracefs", "none", TRACEFS],
                       capture_output=True)


# --------------------------------------------------------------------------
# Independent ground truth
# --------------------------------------------------------------------------

class GroundTruthServer(threading.Thread):
    """A controlled listener that records what it actually received.

    This is the oracle. It is not produced by any candidate, and no candidate
    can influence it: it counts accepted connections and their source ports,
    which is a fact about the network rather than about anybody's telemetry.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        super().__init__(daemon=True)
        self.host = host
        self.accepted: list[int] = []          # source ports
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((host, port))
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
            self.accepted.append(address[1])
            connection.close()

    def stop(self) -> None:
        self._stop.set()
        self._socket.close()


# --------------------------------------------------------------------------
# Candidate B: eBPF tracepoints
# --------------------------------------------------------------------------

#: Three probes, because no one of them can tell the whole truth.
#:
#: * ``sys_enter_connect`` has the right process context and the
#:   application-requested destination, but says nothing about the outcome.
#: * ``sys_exit_connect`` has the errno -- and measurement showed it is
#:   ``EINPROGRESS`` for every *successful* connection Python makes, because
#:   ``settimeout()`` puts the socket in non-blocking mode. Treating a
#:   non-zero return as failure would mislabel every one of them.
#: * ``inet_sock_set_state`` is the only source that knows a connection was
#:   actually established. Its process context is unreliable, because the
#:   transition can happen in softirq while an unrelated task is current.
_BPF_PROGRAM = r"""
tracepoint:syscalls:sys_enter_connect {
  $t = (struct task_struct *)curtask;
  @pending[tid] = 1;
  printf("E|%d|%d|%llu|%s|%llu\n", pid, $t->tgid, $t->start_boottime, comm, nsecs);
}
tracepoint:syscalls:sys_exit_connect /@pending[tid] == 1/ {
  delete(@pending[tid]);
  printf("X|%d|%d|%llu\n", pid, args->ret, nsecs);
}
tracepoint:sock:inet_sock_set_state {
  printf("S|%d|%d|%d|%d|%d|%d|%s|%llu\n",
         pid, args->oldstate, args->newstate, args->dport, args->family,
         args->protocol, comm, nsecs);
}
"""


@dataclass
class StateTransition:
    pid: int
    oldstate: int
    newstate: int
    dport: int
    family: int
    protocol: int
    comm: str
    nsecs: int


#: Kernel TCP states, as the tracepoint reports them.
TCP_ESTABLISHED, TCP_SYN_SENT, TCP_CLOSE = 1, 2, 7


@dataclass
class BpfObservation:
    pid: int
    tgid: int
    start_boottime: int
    comm: str
    nsecs: int
    result: int | None = None


class BpfCandidate:
    """Candidate B. A tracepoint program, read as a line stream.

    bpftrace stands in for a compiled CO-RE object here *for measurement
    only* — what is being measured is whether the tracepoint pair can see
    what Annulon needs, not whether bpftrace is the right shipping vehicle.
    """

    name = "ebpf_tracepoint_connect"

    def __init__(self) -> None:
        self.process: subprocess.Popen | None = None
        self.observations: list[BpfObservation] = []
        self.transitions: list[StateTransition] = []
        self._by_thread: dict[int, BpfObservation] = {}
        self._reader: threading.Thread | None = None
        self.stderr: list[str] = []
        self.attached = False

    def start(self) -> None:
        self.process = subprocess.Popen(
            ["bpftrace", "-e", _BPF_PROGRAM],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            bufsize=1)
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        # "Attaching N probes..." goes to *stdout*, which the reader thread
        # consumes, so it has to be looked for there. Watching stderr alone
        # timed out every run and reported the candidate unavailable --
        # which would have silently excluded the strongest option from the
        # comparison on the strength of a harness bug.
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if self.attached:
                return
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"bpftrace exited early: {' '.join(self.stderr)[:200]}")
            time.sleep(0.1)
        raise RuntimeError("bpftrace never reported its probes attached")

    def _read(self) -> None:
        assert self.process is not None
        threading.Thread(target=self._read_stderr, daemon=True).start()
        for line in self.process.stdout:
            if "Attaching" in line:
                self.attached = True
                continue
            parts = line.strip().split("|")
            if parts[0] == "E" and len(parts) == 6:
                observation = BpfObservation(
                    pid=int(parts[1]), tgid=int(parts[2]),
                    start_boottime=int(parts[3]), comm=parts[4],
                    nsecs=int(parts[5]))
                self.observations.append(observation)
                self._by_thread[observation.pid] = observation
            elif parts[0] == "X" and len(parts) == 4:
                pending = self._by_thread.pop(int(parts[1]), None)
                if pending is not None:
                    pending.result = int(parts[2])
            elif parts[0] == "S" and len(parts) == 9:
                self.transitions.append(StateTransition(
                    pid=int(parts[1]), oldstate=int(parts[2]),
                    newstate=int(parts[3]), dport=int(parts[4]),
                    family=int(parts[5]), protocol=int(parts[6]),
                    comm=parts[7], nsecs=int(parts[8])))

    def _read_stderr(self) -> None:
        assert self.process is not None
        for line in self.process.stderr:
            self.stderr.append(line.strip())

    def stop(self) -> None:
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()


# --------------------------------------------------------------------------
# Candidate D: /proc/net/tcp polling
# --------------------------------------------------------------------------

class ProcPollCandidate(threading.Thread):
    """Candidate D, the obvious baseline, included to be disproved or not.

    It samples `/proc/net/tcp`, so it can only ever see a connection that
    happens to exist at the instant it looks. It also cannot attribute a
    socket to a process without a second pass over `/proc/*/fd`, which is
    slower still.
    """

    name = "proc_net_tcp_poll"

    def __init__(self, interval: float, target_port: int) -> None:
        super().__init__(daemon=True)
        self.interval = interval
        self.target_port = target_port
        self.seen_sockets: set[tuple[str, int]] = set()
        #: TCP state of each sighting. A socket in TIME_WAIT is the *residue*
        #: of a connection that already finished, and counting it as an
        #: observation flatters polling enormously on loopback.
        self.states: Counter = Counter()
        self.samples = 0
        self._stop = threading.Event()

    def run(self) -> None:
        target = f"{self.target_port:04X}"
        while not self._stop.is_set():
            self.samples += 1
            try:
                with open("/proc/net/tcp") as handle:
                    for line in handle.readlines()[1:]:
                        fields = line.split()
                        if len(fields) < 10:
                            continue
                        remote = fields[2]
                        if not remote.endswith(":" + target):
                            continue
                        local = fields[1]
                        inode = int(fields[9])
                        state = fields[3]
                        self.seen_sockets.add((local, inode))
                        self.states[state] += 1
            except OSError:
                pass
            time.sleep(self.interval)

    def stop(self) -> None:
        self._stop.set()


# --------------------------------------------------------------------------
# The workload
# --------------------------------------------------------------------------

_WORKLOAD = r"""
import os, socket, sys, json
host, port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
stat = open("/proc/self/stat").read()
start_ticks = int(stat.split(")")[1].split()[19])
ports = []
for _ in range(count):
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((host, port))
        ports.append(s.getsockname()[1])
    except Exception:
        pass
    finally:
        s.close()
print(json.dumps({"pid": os.getpid(), "start_ticks": start_ticks,
                  "source_ports": ports}))
"""


def run_workload(host: str, port: int, count: int) -> dict:
    """A short-lived process making short-lived connections, then exiting.

    It reports its own identity so attribution can be scored, and it is gone
    by the time the comparison runs — which is the point.
    """
    result = subprocess.run(
        [sys.executable, "-c", _WORKLOAD, host, str(port), str(count)],
        capture_output=True, text=True, timeout=180)
    if result.returncode != 0:
        raise RuntimeError(f"workload failed: {result.stderr[:300]}")
    return json.loads(result.stdout.strip().splitlines()[-1])


# --------------------------------------------------------------------------

def evaluate(count: int, poll_interval: float) -> dict:
    mount_tracefs()
    server = GroundTruthServer()
    server.start()

    bpf = BpfCandidate()
    report: dict = {
        "kernel": os.uname().release, "machine": os.uname().machine,
        "connections_requested": count, "poll_interval_seconds": poll_interval,
        "candidates": {},
    }
    try:
        bpf.start()
    except (RuntimeError, FileNotFoundError, OSError) as exc:
        report["candidates"][BpfCandidate.name] = {
            "available": False, "reason": str(exc)[:200]}
        bpf = None

    poller = ProcPollCandidate(poll_interval, server.port)
    poller.start()
    time.sleep(0.5)

    started = time.monotonic()
    truth = run_workload("127.0.0.1", server.port, count)
    elapsed = time.monotonic() - started

    time.sleep(1.5)                 # let any late events arrive
    poller.stop()
    if bpf is not None:
        bpf.stop()
    time.sleep(0.3)
    server.stop()

    report["ground_truth"] = {
        "workload_pid_in_this_namespace": truth["pid"],
        "workload_start_ticks": truth["start_ticks"],
        "connections_the_workload_believes_it_made": len(truth["source_ports"]),
        "connections_the_server_actually_accepted": len(server.accepted),
        "elapsed_seconds": round(elapsed, 3),
        "connections_per_second": round(count / elapsed, 1) if elapsed else None,
    }

    if bpf is not None:
        ours = [o for o in bpf.observations if o.comm.startswith("python")]
        instances = {(o.tgid, o.start_boottime) for o in ours}
        with_result = [o for o in ours if o.result is not None]
        report["candidates"][BpfCandidate.name] = {
            "available": True,
            "observations_total": len(bpf.observations),
            "observations_attributable_to_the_workload": len(ours),
            "capture_rate": round(len(ours) / count, 4) if count else None,
            "distinct_process_instances_seen": len(instances),
            "carries_process_start_time": bool(instances) and all(
                start > 0 for _, start in instances),
            "connect_results_paired": len(with_result),
            "result_codes": dict(Counter(o.result for o in with_result)),
            "host_pids_seen": sorted({o.tgid for o in ours})[:3],
            "state_transitions": _summarise_transitions(bpf.transitions,
                                                        server.port),
            "namespace_note": "PIDs are from the sensor's PID namespace, not "
                              "the workload's -- see the ground truth pid",
        }

    report["candidates"][ProcPollCandidate.name] = {
        "available": True,
        "samples_taken": poller.samples,
        "distinct_sockets_observed": len(poller.seen_sockets),
        "capture_rate": round(len(poller.seen_sockets) / count, 4) if count else None,
        "attributes_to_a_process": False,
        "sightings_by_tcp_state": {_TCP_STATES.get(k, k): v
                                   for k, v in poller.states.items()},
        "established_sightings": poller.states.get("01", 0),
        "time_wait_sightings": poller.states.get("06", 0),
        "note": "a socket seen in /proc/net/tcp carries an inode, not a "
                "process; attribution needs a second scan of /proc/*/fd, "
                "which is slower again and races the same way",
        "caveat": "most sightings are TIME_WAIT -- the residue of a "
                  "connection that already closed, not an observation of it "
                  "happening. The capture rate here flatters polling badly.",
    }
    return report


def _summarise_transitions(transitions: list, target_port: int) -> dict:
    """What the state tracepoint saw, and whether it can be trusted for PID.

    The established count is the only honest answer to "did the connection
    actually happen"; the syscall return cannot give it. The comm breakdown
    exists to show whether the process context at that moment is the
    connecting process or whatever happened to be running.
    """
    ours = [t for t in transitions if t.dport == target_port]
    to_syn_sent = [t for t in ours if t.newstate == TCP_SYN_SENT]
    to_established = [t for t in ours if t.newstate == TCP_ESTABLISHED]
    return {
        "transitions_to_target_port": len(ours),
        "attempts_syn_sent": len(to_syn_sent),
        "established": len(to_established),
        "comm_at_established": dict(Counter(t.comm for t in to_established)),
        "comm_at_syn_sent": dict(Counter(t.comm for t in to_syn_sent)),
        "families_seen": sorted({t.family for t in ours}),
        "note": "family 2 = AF_INET, 10 = AF_INET6. The established count is "
                "the only source that knows a connection succeeded; the "
                "connect() return value does not.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--poll-interval", type=float, default=0.01)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.count, args.poll_interval), indent=2,
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
