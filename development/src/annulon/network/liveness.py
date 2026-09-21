"""Prove the network observation path still works, rather than assuming it.

ADR-041 established this for the process sensor: a descriptor that is open
and a thread that is alive assert almost nothing, because both survive the
kernel ceasing delivery. The same argument applies here, and the tracefs
sensor has extra ways to go quiet that no counter reports -- a tracepoint
disabled underneath us, a private instance removed, a reader that stopped
consuming while the ring buffer silently wraps.

So the monitor causes a real, harmless TCP connection and then checks that
the *selected primary semantic* came back: the `TCP_CLOSE -> TCP_SYN_SENT`
transition that 04C chose as the only source carrying both a destination and
trustworthy process context (ADR-053, KF-45).

Three choices carry the weight.

**The receipt is taken after the bounded queue and the normaliser**, not at
the parser. A probe satisfied at the earliest convenient point would report
healthy while the queue was saturated and every real observation was being
dropped -- which is precisely the state an operator needs to hear about.

**The probe is never satisfied by an event it did not cause.** A fresh
ephemeral port is the nonce, and the match additionally requires our own
process identity, the loopback destination, the expected operation and
transport, and an arrival inside the current window. Another process
connecting to the same listener does not make Annulon healthy.

**A successful probe is necessary, not sufficient.** If the kernel ring
buffer or the userspace queue lost anything across the probe interval, the
path demonstrably works *and* something was missed, so the epoch is degraded
and its silence is not trustworthy.

What this does not prove: external connectivity, DNS, or that any particular
remote host is reachable. It proves that a kernel network event reaches an
Annulon observation.
"""

from __future__ import annotations

import os
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable

from annulon.agent.liveness import LivenessResult
from annulon.collectors.base import SensorHealth, SensorStats
from annulon.network.contract import (
    AddressFamily, ConnectionOutcome, Direction, NetworkObservation,
    NetworkOperation, Transport,
)
from annulon.network.tracefs import LossCounters

__all__ = ["NetworkLivenessProbe", "NetworkLivenessMonitor",
           "NetworkLivenessReceipt", "network_collection_health",
           "DEFAULT_DEADLINE_SECONDS", "CLOCK_TOLERANCE_SECONDS"]

#: Small and deterministic. Not a product SLO: no owner-approved latency
#: target exists, and inventing one here would turn a test convenience into
#: a claim about production timing.
DEFAULT_DEADLINE_SECONDS = 5.0
#: `observed_at` is reconstructed from `/proc/stat` btime plus the trace
#: timestamp, and btime has one-second resolution. The window is widened by
#: this much so a correct probe is not rejected by clock reconstruction
#: error. It is a tolerance on *our* arithmetic, not a grace period for
#: stale events: the fresh port and the pid still have to match.
CLOCK_TOLERANCE_SECONDS = 3.0


class NetworkLivenessProbe:
    """One attempt to make the kernel produce an observation we can recognise.

    The listener is bound on loopback with port 0, so the kernel hands us a
    port no other socket currently holds. That port is the nonce: an
    observation naming it could only have been caused by a connection to this
    listener, which existed for the duration of this probe alone.
    """

    def __init__(self, *, family: AddressFamily = AddressFamily.IPV4,
                 expected_pid: int | None = None,
                 network_namespace: int | None = None) -> None:
        self.probe_id = uuid.uuid4().hex[:16]
        self.family = family
        #: The pid *as the sensor observes it*. tracefs reports pids in its
        #: own namespace, so an agent in a separate pid namespace must be
        #: told its externally visible pid rather than guessing. Guessing
        #: would produce a probe that can never match, and a sensor that
        #: reports failure forever while working perfectly.
        self.expected_pid = os.getpid() if expected_pid is None else expected_pid
        self.network_namespace = network_namespace
        self._listener: socket.socket | None = None
        self.port: int | None = None
        self.fired_at: datetime | None = None
        self.deadline_at: datetime | None = None
        self.address = "127.0.0.1" if family is AddressFamily.IPV4 else "::1"

    @property
    def socket_family(self) -> int:
        """The AF_* constant this probe binds and connects with.

        One site rather than two identical ternaries: the duplicate could not
        be tested on its own, and swapping it behaved differently per
        platform, which made the defect invisible on one of them.
        """
        return (socket.AF_INET if self.family is AddressFamily.IPV4
                else socket.AF_INET6)

    def open(self) -> int:
        """Bind the listener and return the fresh port."""
        listener = socket.socket(self.socket_family, socket.SOCK_STREAM)
        # Deliberately no SO_REUSEADDR: the point is a port nothing else is
        # using, and reuse would weaken the nonce.
        listener.bind((self.address, 0))
        listener.listen(1)
        listener.settimeout(0.5)
        self._listener = listener
        self.port = listener.getsockname()[1]
        return self.port

    def fire(self, *, deadline_seconds: float = DEFAULT_DEADLINE_SECONDS) -> bool:
        """Make one connection to our own listener. Returns whether it opened.

        The harness's independent view of whether the connection happened is
        this return value plus the accepted socket -- deliberately separate
        from whether Annulon *observed* it.
        """
        if self._listener is None:
            self.open()
        self.fired_at = datetime.now(timezone.utc)
        self.deadline_at = self.fired_at + timedelta(seconds=deadline_seconds)
        client = socket.socket(self.socket_family, socket.SOCK_STREAM)
        client.settimeout(2.0)
        connected = False
        try:
            client.connect((self.address, self.port))
            connected = True
            try:
                accepted, _ = self._listener.accept()
                accepted.close()
            except (OSError, socket.timeout):
                pass
        except OSError:
            connected = False
        finally:
            client.close()
        return connected

    def matches(self, observation: NetworkObservation) -> bool:
        """Whether this observation is the one this probe caused.

        Every clause is here because dropping it would let something else
        satisfy the probe. The port alone is not enough: another local
        process could connect to the listener while it is open, and a health
        check that any process can satisfy is a health check an attacker can
        satisfy.
        """
        if self.port is None or self.fired_at is None:
            return False
        if not isinstance(observation, NetworkObservation):
            return False
        # The selected primary semantic, not "any network event".
        if observation.operation is not NetworkOperation.CONNECT_ATTEMPT:
            return False
        if observation.transport is not Transport.TCP:
            return False
        if observation.direction is not Direction.OUTBOUND:
            return False
        remote = observation.remote
        if remote is None:
            return False
        if remote.port != self.port:
            return False
        if remote.family is not self.family:
            return False
        if not remote.is_loopback:
            return False
        # Our own process. This is what stops another process's connection to
        # the same listener from certifying Annulon's sensor.
        if observation.process.pid != self.expected_pid:
            return False
        if (self.network_namespace is not None
                and observation.network_namespace is not None
                and observation.network_namespace != self.network_namespace):
            return False
        # Inside this probe's window. A delayed item from an earlier probe
        # carries an earlier timestamp and is refused.
        earliest = self.fired_at - timedelta(seconds=CLOCK_TOLERANCE_SECONDS)
        latest = (self.deadline_at or self.fired_at) + timedelta(
            seconds=CLOCK_TOLERANCE_SECONDS)
        return earliest <= observation.observed_at <= latest

    def close(self) -> None:
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None


@dataclass(frozen=True)
class NetworkLivenessReceipt:
    """A probe outcome together with what was lost while it ran.

    The two are kept in one record because they are only meaningful
    together: a probe that succeeded during an interval in which the ring
    buffer wrapped proves the path works and proves nothing about what was
    missed.
    """

    result: LivenessResult
    loss_before: LossCounters
    loss_after: LossCounters
    #: True when the connection itself was made. Separating this from
    #: `result.observed` distinguishes "Annulon could not see it" from "the
    #: probe never happened", which need different responses.
    connection_made: bool = True

    @property
    def loss_delta(self) -> int:
        return max(0, self.loss_after.total - self.loss_before.total)

    @property
    def observed(self) -> bool:
        return self.result.observed

    @property
    def clean(self) -> bool:
        """The path demonstrably works and nothing was lost while proving it."""
        return self.observed and self.loss_delta == 0

    def to_dict(self) -> dict:
        return {"result": self.result.to_dict(),
                "loss_before": self.loss_before.to_dict(),
                "loss_after": self.loss_after.to_dict(),
                "loss_delta": self.loss_delta,
                "connection_made": self.connection_made,
                "clean": self.clean}


@dataclass
class NetworkLivenessMonitor:
    """Runs probes and remembers what happened, without consuming evidence.

    The monitor never drains the sensor. Observations are offered to it by
    whatever is already draining, through :meth:`consider`, and it returns
    only whether the observation was its own probe. Nothing is removed,
    reordered or held back — ADR-041's rule that self-checking must not
    destroy evidence, applied to a pipeline that has a bounded queue in it.
    """

    deadline_seconds: float = DEFAULT_DEADLINE_SECONDS
    enabled: bool = True
    history_limit: int = 20
    expected_pid: int | None = None
    network_namespace: int | None = None
    _history: list[NetworkLivenessReceipt] = field(default_factory=list)
    _pending: NetworkLivenessProbe | None = field(default=None)
    _pending_matched: bool = field(default=False)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    #: Ports used by probes so far, so a late duplicate of an old probe is
    #: recognisable as internal traffic rather than mistaken for a workload.
    _known_ports: set[int] = field(default_factory=set)

    # -- state ------------------------------------------------------------

    @property
    def last(self) -> NetworkLivenessReceipt | None:
        return self._history[-1] if self._history else None

    @property
    def history(self) -> tuple[NetworkLivenessReceipt, ...]:
        return tuple(self._history)

    @property
    def healthy(self) -> bool:
        """Never probed is not healthy.

        Reporting health on no evidence is the habit ADR-041 exists to break,
        and it is the single most likely way this module would be wrong.
        """
        receipt = self.last
        return receipt is not None and receipt.clean

    @property
    def ever_succeeded(self) -> bool:
        return any(receipt.observed for receipt in self._history)

    def status(self) -> str:
        """A short description using the project's existing vocabulary."""
        receipt = self.last
        if receipt is None:
            return "NEVER_PROBED"
        if not receipt.observed:
            return "FAILED"
        if receipt.loss_delta:
            return "DEGRADED"
        return "HEALTHY"

    # -- the pipeline hook -------------------------------------------------

    def consider(self, observation: NetworkObservation) -> bool:
        """Offer one normalised observation. Returns whether it was our probe.

        Called by the ordinary consumer *after* the bounded queue and the
        normaliser, so a saturated or broken userspace path cannot be
        reported healthy on the strength of the parser still working.

        The observation is never consumed: the caller keeps it and decides
        what to do with it, which for a probe match is to mark it internal
        rather than to discard it (health accounting has to be able to prove
        the sensor saw the probe).
        """
        with self._lock:
            probe = self._pending
            if probe is None:
                return False
            if not probe.matches(observation):
                return False
            self._pending_matched = True
            return True

    def is_internal(self, observation: NetworkObservation) -> bool:
        """Whether this observation is Annulon's own health traffic.

        Decided from in-process probe state — the set of ports this monitor
        actually bound — never from a field on the observation. An event
        that could declare itself internal would be a bypass any workload
        could use.
        """
        if not isinstance(observation, NetworkObservation):
            return False
        remote = observation.remote
        if remote is None or not remote.is_loopback:
            return False
        if observation.process.pid != (self.expected_pid
                                       if self.expected_pid is not None
                                       else os.getpid()):
            return False
        with self._lock:
            return remote.port in self._known_ports

    # -- running a probe ---------------------------------------------------

    def run(self, pump: Callable[[], Iterable[NetworkObservation]],
            loss: Callable[[], LossCounters], *,
            sleep: Callable[[float], None] = time.sleep,
            cancel: threading.Event | None = None) -> NetworkLivenessReceipt:
        """Fire a probe and wait, bounded, for it to come back.

        ``pump`` advances the ordinary pipeline one step and returns whatever
        normalised observations it produced; the monitor inspects them and
        hands them straight back to the caller's own handling. ``loss`` reads
        the current counters so the interval's delta can be computed.

        ``cancel`` lets a shutdown abandon a pending probe immediately. Without
        it a stop would have to wait out the deadline, and a health check that
        delays shutdown is a health check that gets removed (KF-44's lesson,
        one layer up).
        """
        probe = NetworkLivenessProbe(expected_pid=self.expected_pid,
                                     network_namespace=self.network_namespace)
        port = probe.open()
        before = loss()
        with self._lock:
            self._pending = probe
            self._pending_matched = False
            self._known_ports.add(port)
        started = time.monotonic()
        connected = False
        try:
            connected = probe.fire(deadline_seconds=self.deadline_seconds)
            deadline = started + self.deadline_seconds
            while time.monotonic() < deadline:
                if cancel is not None and cancel.is_set():
                    break
                for observation in pump():
                    # Offered, never taken. The caller's pump owns these and
                    # keeps them; the monitor only reads.
                    self.consider(observation)
                with self._lock:
                    matched = self._pending_matched
                if matched:
                    break
                sleep(0.02)
            with self._lock:
                observed = self._pending_matched
        finally:
            probe.close()
            with self._lock:
                self._pending = None

        latency = round(time.monotonic() - started, 4) if observed else None
        after = loss()
        detail = self._detail(observed, connected, before, after)
        receipt = NetworkLivenessReceipt(
            result=LivenessResult(
                probe_id=probe.probe_id, observed=observed,
                latency_seconds=latency,
                checked_at=datetime.now(timezone.utc), detail=detail),
            loss_before=before, loss_after=after, connection_made=connected)
        with self._lock:
            self._history.append(receipt)
            if len(self._history) > self.history_limit:
                self._history = self._history[-self.history_limit:]
        return receipt

    @staticmethod
    def _detail(observed: bool, connected: bool, before: LossCounters,
                after: LossCounters) -> str:
        delta = max(0, after.total - before.total)
        if not connected:
            return ("the probe connection itself did not open, so this says "
                    "nothing about the sensor")
        if not observed:
            return ("the probe connection was made but no matching "
                    "observation arrived: the sensor may be running and no "
                    "longer delivering")
        if delta:
            return (f"the probe was observed, but {delta} event(s) were lost "
                    "during the interval, so silence in this epoch is not "
                    "trustworthy")
        return "the probe was observed and no loss occurred in the interval"

    def record_external(self, receipt: NetworkLivenessReceipt) -> None:
        """For an experiment that runs the probe itself."""
        with self._lock:
            self._history.append(receipt)
            self._history = self._history[-self.history_limit:]


def network_collection_health(sensor_health: dict,
                              monitor: NetworkLivenessMonitor) -> SensorHealth:
    """Combine sensor state and liveness into the project's existing model.

    Deliberately returns :class:`SensorHealth` rather than a new type, so
    detectors keep asking the one question they already ask —
    ``trustworthy_absence`` — and there is no second, subtly different notion
    of health to keep in step (ADR-039).

    A failed probe removes the right to treat silence as meaningful. It does
    **not** become evidence that something bad happened: a blind sensor tells
    you nothing about the network, in either direction.
    """
    loss = sensor_health.get("loss", {}) or {}
    stats = SensorStats(
        dropped=int(loss.get("total", 0) or 0),
        decode_errors=int(sensor_health.get("unparsed_lines", 0) or 0))
    running = bool(sensor_health.get("running"))
    status = monitor.status()

    reasons = list(sensor_health.get("degraded_reasons", []) or [])
    if status == "NEVER_PROBED":
        reasons.append("the network path has never been proved: absence of "
                       "observations means nothing yet")
    elif status == "FAILED":
        reasons.append("the most recent liveness probe was not observed")
    elif status == "DEGRADED":
        reasons.append("events were lost during the last liveness interval")

    attests = (running and status == "HEALTHY"
               and bool(sensor_health.get("attests_completeness")))
    blind_spot = "; ".join(reasons)
    if not attests and not blind_spot:
        blind_spot = "completeness is not attested"
    return SensorHealth(
        running=running,
        detail=f"liveness={status}",
        stats=stats,
        attests_completeness=attests,
        blind_spot=blind_spot)
