"""Probe lifecycle: issue, correlate, expire -- exactly once, always bounded.

This module replaces ``HostProber`` plus the probe-reply branch of
``processPacketInMessage``. Four legacy defects are structural here rather
than incidental:

* **No timeout existed.** ``probedPorts`` entries were created and never
  resolved, so the "no reply implies legitimate migration" conclusion was
  unreachable and the map grew for the process lifetime. Here every probe
  carries a deadline and ``expire()`` resolves it.
* **Replies could not be authenticated.** The correlation test compared
  source IP, source MAC and a hardcoded controller IP -- all forgeable by an
  on-segment attacker. Here a single-use unguessable nonce must match.
* **Shared mutable probe fields.** ``targetMAC``/``targetIP`` were instance
  fields overwritten by each probe, so concurrent probes clobbered one
  another. Here every probe is an immutable value in a keyed table.
* **Unbounded growth.** Here the outstanding set has an explicit limit and
  refuses rather than evicting.

The manager holds no clock: every method that needs time takes it as an
argument or reads an injected ``Clock``. That keeps expiry deterministic and
immune to wall-clock steps (ADR-009).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Final, Iterator

from sdnguard.clock import Clock, SystemClock
from sdnguard.domain.events import (
    ProbeMethod,
    ProbeOutcome,
    ProbeRequest,
    ProbeResult,
)
from sdnguard.domain.host import HostIdentity, MacAddress
from sdnguard.domain.identity import DatapathId, InvalidIdentity, PortIdentity, _ValueObject

__all__ = [
    "OutstandingProbe",
    "ProbeManager",
    "ProbeManagerFull",
    "ProbeRejected",
    "DEFAULT_MAX_OUTSTANDING",
    "DEFAULT_TIMEOUT",
]

DEFAULT_MAX_OUTSTANDING: Final = 1024
DEFAULT_TIMEOUT: Final = timedelta(seconds=3)


class ProbeManagerFull(Exception):
    """The outstanding-probe table refused to grow.

    Refusing matters: evicting the oldest probe would let an attacker who can
    force many movements flush the validation of their own hijack.
    """


class ProbeRejected(Exception):
    """A probe could not be accepted -- for example a duplicate for a host
    that already has one outstanding."""


@dataclass(frozen=True)
class OutstandingProbe(_ValueObject):
    """A probe awaiting resolution, plus the connection generation it was
    issued under."""

    __slots__ = ("request", "mac", "generation", "monotonic_deadline")
    request: ProbeRequest
    mac: MacAddress
    generation: int
    monotonic_deadline: float

    def __post_init__(self) -> None:
        if not isinstance(self.request, ProbeRequest):
            raise InvalidIdentity("request must be a ProbeRequest")

    @property
    def correlation_id(self) -> str:
        return self.request.correlation_id

    @property
    def target_port(self) -> PortIdentity:
        return self.request.target_port

    def __str__(self) -> str:
        return f"{self.request} for {self.mac}"


class ProbeManager:
    """Bounded table of outstanding probes with exactly-once resolution."""

    def __init__(self, *, clock: Clock | None = None,
                 timeout: timedelta = DEFAULT_TIMEOUT,
                 max_outstanding: int = DEFAULT_MAX_OUTSTANDING) -> None:
        if timeout <= timedelta(0):
            raise ValueError("timeout must be positive")
        if max_outstanding < 1:
            raise ValueError("max_outstanding must be positive")
        self._clock = clock or SystemClock()
        self._timeout = timeout
        self._max = max_outstanding
        self._by_id: dict[str, OutstandingProbe] = {}
        self._by_mac: dict[MacAddress, str] = {}
        self._resolved_ids: set[str] = set()

    # -- issuing ---------------------------------------------------------

    def issue(self, identity: HostIdentity, target_port: PortIdentity, *,
              generation: int = 0,
              method: ProbeMethod = ProbeMethod.ARP,
              timeout: timedelta | None = None) -> ProbeRequest:
        """Create and register a probe. Does not send it: transmission is the
        adapter's job, which keeps this module framework-independent."""
        mac = identity.mac
        if mac in self._by_mac:
            raise ProbeRejected(
                f"{mac} already has an outstanding probe "
                f"{self._by_mac[mac][:8]}; one at a time per host")
        if len(self._by_id) >= self._max:
            raise ProbeManagerFull(
                f"{len(self._by_id)} probes outstanding (limit {self._max}); "
                "refusing rather than evicting, so an attacker cannot flush "
                "the validation of their own move")

        window = timeout or self._timeout
        request = ProbeRequest.create(identity, target_port, self._clock.now(),
                                      window, method)
        entry = OutstandingProbe(request, mac, generation,
                                 self._clock.monotonic() + window.total_seconds())
        self._by_id[request.correlation_id] = entry
        self._by_mac[mac] = request.correlation_id
        return request

    # -- correlation -----------------------------------------------------

    def correlate(self, correlation_id: str, *, source_port: PortIdentity,
                  mac: MacAddress) -> ProbeResult | None:
        """Match an observed reply to an outstanding probe.

        Returns ``None`` when nothing matches -- an unsolicited or forged
        reply is not an error, it is simply not evidence. All three checks
        must pass: the nonce is known, the MAC is the probed host, and the
        reply arrived on the port we probed. The legacy check omitted the
        nonce entirely and so could be satisfied by any on-segment attacker.
        """
        entry = self._by_id.get(correlation_id)
        if entry is None:
            return None
        if entry.mac != mac:
            return None
        if entry.target_port != source_port:
            return None
        return self._resolve(entry, ProbeOutcome.REPLIED,
                             "reply matched nonce, host and probed port")

    # -- resolution ------------------------------------------------------

    def expire(self, now: float | None = None) -> list[ProbeResult]:
        """Resolve every probe whose monotonic deadline has passed."""
        moment = self._clock.monotonic() if now is None else now
        due = [e for e in self._by_id.values() if moment >= e.monotonic_deadline]
        return [self._resolve(e, ProbeOutcome.EXPIRED,
                              "deadline passed with no matching reply")
                for e in sorted(due, key=lambda e: e.monotonic_deadline)]

    def cancel(self, mac: MacAddress, reason: str = "cancelled") -> ProbeResult | None:
        correlation_id = self._by_mac.get(mac)
        if correlation_id is None:
            return None
        return self._resolve(self._by_id[correlation_id],
                             ProbeOutcome.CANCELLED, reason)

    def mark_undeliverable(self, correlation_id: str,
                           reason: str = "port or switch unavailable") -> ProbeResult | None:
        entry = self._by_id.get(correlation_id)
        if entry is None:
            return None
        return self._resolve(entry, ProbeOutcome.UNDELIVERABLE, reason)

    def cancel_switch(self, dpid: DatapathId,
                      reason: str = "switch disconnected") -> list[ProbeResult]:
        """A probe aimed at a departed switch can never be answered, and the
        port may be a different physical link when it returns."""
        doomed = [e for e in self._by_id.values()
                  if e.target_port.datapath_id == dpid]
        return [self._resolve(e, ProbeOutcome.CANCELLED, reason)
                for e in sorted(doomed, key=lambda e: e.correlation_id)]

    def cancel_stale_generations(self, dpid: DatapathId, current_generation: int,
                                 ) -> list[ProbeResult]:
        """Resolve probes issued under a previous connection generation."""
        doomed = [e for e in self._by_id.values()
                  if e.target_port.datapath_id == dpid
                  and e.generation != current_generation]
        return [self._resolve(e, ProbeOutcome.CANCELLED,
                              f"issued under generation {e.generation}, "
                              f"switch is now at {current_generation}")
                for e in sorted(doomed, key=lambda e: e.correlation_id)]

    def _resolve(self, entry: OutstandingProbe, outcome: ProbeOutcome,
                 detail: str) -> ProbeResult:
        """The single exit path. A probe leaves the table exactly once."""
        del self._by_id[entry.correlation_id]
        if self._by_mac.get(entry.mac) == entry.correlation_id:
            del self._by_mac[entry.mac]
        self._resolved_ids.add(entry.correlation_id)
        if len(self._resolved_ids) > self._max * 4:
            # Bounded replay memory: enough to recognise a late duplicate,
            # not enough to grow without limit.
            self._resolved_ids = set(list(self._resolved_ids)[-self._max * 2:])
        return ProbeResult.of(entry.correlation_id, outcome, self._clock.now(), detail)

    # -- queries ---------------------------------------------------------

    def outstanding_for(self, mac: MacAddress) -> OutstandingProbe | None:
        correlation_id = self._by_mac.get(mac)
        return self._by_id.get(correlation_id) if correlation_id else None

    def get(self, correlation_id: str) -> OutstandingProbe | None:
        return self._by_id.get(correlation_id)

    def was_resolved(self, correlation_id: str) -> bool:
        """True for a probe this manager has already retired. Lets a caller
        distinguish a late duplicate from an entirely unknown nonce."""
        return correlation_id in self._resolved_ids

    def next_deadline(self) -> float | None:
        return min((e.monotonic_deadline for e in self._by_id.values()), default=None)

    def __len__(self) -> int:
        return len(self._by_id)

    def __iter__(self) -> Iterator[OutstandingProbe]:
        return iter(sorted(self._by_id.values(), key=lambda e: e.monotonic_deadline))

    @property
    def capacity(self) -> int:
        return self._max
