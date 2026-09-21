"""Turn raw trace lines into Annulon network observations.

The boundary between a kernel mechanism and the domain model. Nothing above
this layer knows what tracefs is, which is what keeps the sensor replaceable
(doctrine §46): a different mechanism supplies different `RawEvent`s and this
module is the only thing that changes.

The mapping is not the obvious one, and the reason is measured rather than
assumed (KF-45):

* `TCP_CLOSE -> TCP_SYN_SENT` becomes ``CONNECT_ATTEMPT``. It is the only
  source that carries a destination *and* trustworthy process context, and
  being an inet tracepoint it cannot be confused by AF_UNIX traffic.
* `-> TCP_ESTABLISHED` becomes ``CONNECTION_ESTABLISHED``, but its process
  context is discarded: that transition frequently runs in softirq, where the
  current task is whatever happened to be scheduled. It is attributed by
  matching the flow, never by believing the PID.
* `sys_exit_connect` becomes ``CONNECT_RESULT``, carrying the errno — which
  is usually `EINPROGRESS` and therefore means *pending*.

An event that cannot be normalised honestly is dropped and counted, never
guessed at.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from annulon.network.contract import (
    AddressFamily, AttributionConfidence, ConnectionOutcome, Direction,
    Endpoint, NetworkContractError, NetworkObservation, NetworkOperation,
    ProcessRef, SocketSemantic, Transport, outcome_for_errno,
)
from annulon.network.tracefs import RawEvent

__all__ = ["NetworkNormalizer", "NormalizationStats", "TCP_STATES"]

TCP_STATES = {
    "TCP_ESTABLISHED": 1, "TCP_SYN_SENT": 2, "TCP_SYN_RECV": 3,
    "TCP_FIN_WAIT1": 4, "TCP_FIN_WAIT2": 5, "TCP_TIME_WAIT": 6,
    "TCP_CLOSE": 7, "TCP_CLOSE_WAIT": 8, "TCP_LAST_ACK": 9,
    "TCP_LISTEN": 10, "TCP_CLOSING": 11,
}
_FAMILIES = {"AF_INET": AddressFamily.IPV4, "AF_INET6": AddressFamily.IPV6}
_PROTOCOLS = {"IPPROTO_TCP": Transport.TCP, "IPPROTO_UDP": Transport.UDP}
#: tracefs prints an unset v6 address as this.
_UNSET_V6 = {"::", "::ffff:0.0.0.0", ""}


@dataclass
class NormalizationStats:
    """What could not be turned into an observation, and why.

    Counted rather than logged and forgotten: a normaliser quietly dropping
    a third of its input is indistinguishable from a quiet network unless
    someone is keeping score.
    """

    produced: int = 0
    ignored_other_states: int = 0
    ignored_non_ip: int = 0
    malformed_address: int = 0
    unusable_fields: int = 0
    unattributable_discarded_pid: int = 0

    @property
    def dropped(self) -> int:
        return (self.malformed_address + self.unusable_fields)

    def to_dict(self) -> dict:
        return {"produced": self.produced,
                "ignored_other_states": self.ignored_other_states,
                "ignored_non_ip": self.ignored_non_ip,
                "malformed_address": self.malformed_address,
                "unusable_fields": self.unusable_fields,
                "unattributable_discarded_pid": self.unattributable_discarded_pid,
                "dropped": self.dropped}


class NetworkNormalizer:
    """Raw events in, domain observations out.

    Stateless apart from an id counter and a small correlation window, so it
    can be driven from a test with hand-written events and behave exactly as
    it does against a live kernel.
    """

    def __init__(self, *, sensor_id: str = "tracefs_network",
                 boot_time: datetime | None = None,
                 pid_namespace: int | None = None,
                 self_test_port: int | None = None) -> None:
        self._sensor_id = sensor_id
        #: Trace timestamps are seconds since boot. Without a boot wall-clock
        #: they cannot be placed on a timeline shared with other sensors.
        self._boot_time = boot_time or self._read_boot_time()
        self._pid_namespace = pid_namespace
        #: Observations to this port are Annulon's own liveness probe. They
        #: are marked, not discarded: health accounting has to prove the
        #: sensor saw them.
        self._self_test_port = self_test_port
        self._counter = 0
        self.stats = NormalizationStats()

    @staticmethod
    def _read_boot_time() -> datetime:
        try:
            with open("/proc/stat") as handle:
                for line in handle:
                    if line.startswith("btime "):
                        return datetime.fromtimestamp(int(line.split()[1]),
                                                      tz=timezone.utc)
        except (OSError, ValueError, IndexError):
            pass
        return datetime.now(timezone.utc)

    def _next_id(self) -> str:
        self._counter += 1
        return f"netobs-{self._counter:012d}"

    def _when(self, event: RawEvent) -> datetime:
        return self._boot_time + timedelta(seconds=event.timestamp)

    # -- entry point -------------------------------------------------------

    def normalize(self, event: RawEvent) -> NetworkObservation | None:
        """One raw event to at most one observation.

        Returns ``None`` for anything that cannot be represented truthfully.
        That is the common case: most state transitions are not connection
        attempts, and dropping them is correct rather than lossy.
        """
        if not isinstance(event, RawEvent):
            return None
        try:
            if event.kind == "inet_sock_set_state":
                return self._from_state(event)
            if event.kind == "sys_exit_connect":
                return self._from_connect_result(event)
        except NetworkContractError:
            # The contract refused it. That is the contract working; the
            # observation is dropped rather than forced through.
            self.stats.unusable_fields += 1
            return None
        return None

    def normalize_all(self, events) -> list[NetworkObservation]:
        produced = []
        for event in events:
            observation = self.normalize(event)
            if observation is not None:
                produced.append(observation)
        return produced

    # -- state transitions --------------------------------------------------

    def _from_state(self, event: RawEvent) -> NetworkObservation | None:
        fields = event.fields
        new_state = fields.get("newstate", "")
        old_state = fields.get("oldstate", "")

        if new_state == "TCP_SYN_SENT":
            operation = NetworkOperation.CONNECT_ATTEMPT
            outcome = ConnectionOutcome.UNKNOWN
        elif new_state == "TCP_ESTABLISHED":
            operation = NetworkOperation.CONNECTION_ESTABLISHED
            outcome = ConnectionOutcome.ESTABLISHED
        elif old_state == "TCP_ESTABLISHED":
            operation = NetworkOperation.CONNECTION_CLOSED
            outcome = ConnectionOutcome.UNKNOWN
        else:
            self.stats.ignored_other_states += 1
            return None

        family = _FAMILIES.get(fields.get("family", ""))
        transport = _PROTOCOLS.get(fields.get("protocol", ""))
        if family is None or transport is None:
            self.stats.ignored_non_ip += 1
            return None

        local = self._endpoint(fields, "saddr", "saddrv6", "sport", family)
        remote = self._endpoint(fields, "daddr", "daddrv6", "dport", family)
        if local is None or remote is None:
            self.stats.malformed_address += 1
            return None
        # A dual-stack socket reports AF_INET6 while carrying a v4-mapped
        # address, and the packet on the wire is IPv4. Recording that as IPv6
        # would let an IPv4 policy miss it and an IPv6 policy match traffic
        # that is not IPv6 -- the same class of mistake as KF-38, one layer
        # up. Both endpoints are unmapped together or not at all.
        if (local.family is AddressFamily.IPV6
                and remote.family is AddressFamily.IPV6):
            unmapped_local = self._unmap(local)
            unmapped_remote = self._unmap(remote)
            if unmapped_local is not None and unmapped_remote is not None:
                local, remote = unmapped_local, unmapped_remote

        # An ESTABLISHED transition usually runs in softirq, where the
        # current task is unrelated to the connection. Its PID is therefore
        # not used for attribution -- the observation says NONE rather than
        # naming a process that merely happened to be running.
        if event.attributable:
            process = ProcessRef(
                pid=event.pid, tgid=event.pid, comm=event.comm[:64],
                pid_namespace=self._pid_namespace,
                confidence=AttributionConfidence.PID_ONLY)
            semantic = SocketSemantic.CONNECT_INITIATOR
        else:
            self.stats.unattributable_discarded_pid += 1
            process = ProcessRef(pid=0, confidence=AttributionConfidence.NONE)
            semantic = SocketSemantic.CURRENT_TASK

        return NetworkObservation(
            observation_id=self._next_id(), operation=operation,
            transport=transport, direction=Direction.OUTBOUND,
            process=process, local=local, remote=remote,
            observed_at=self._when(event), sensor_id=self._sensor_id,
            outcome=outcome, socket_semantic=semantic,
            destination_semantic="post_routing_socket_state",
            network_namespace=None,
            socket_key=f"{local}->{remote}",
            is_self_test=self._is_self_test(remote))

    def _endpoint(self, fields: dict, v4_key: str, v6_key: str,
                  port_key: str, family: AddressFamily) -> Endpoint | None:
        """Build an endpoint, preferring the field that matches the family.

        tracefs emits both `daddr` and `daddrv6` on every transition; for an
        IPv4 socket the v6 form is a mapped address, and for an IPv6 socket
        the v4 form is unset. Reading the wrong one produces an address that
        parses but is not what the socket used.
        """
        raw_port = fields.get(port_key)
        if raw_port is None or not raw_port.isdigit():
            return None
        port = int(raw_port)
        if family is AddressFamily.IPV4:
            address = fields.get(v4_key, "")
        else:
            address = fields.get(v6_key, "")
            if address in _UNSET_V6:
                return None
        if not address:
            return None
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return None
        if parsed.version != family.version:
            return None
        try:
            return Endpoint(str(parsed), port, family)
        except NetworkContractError:
            return None

    @staticmethod
    def _unmap(endpoint: Endpoint) -> Endpoint | None:
        """Return the IPv4 form of a v4-mapped address, or ``None``."""
        parsed = ipaddress.ip_address(endpoint.address)
        mapped = getattr(parsed, "ipv4_mapped", None)
        if mapped is None:
            return None
        try:
            return Endpoint(str(mapped), endpoint.port, AddressFamily.IPV4)
        except NetworkContractError:
            return None

    def _is_self_test(self, remote: Endpoint) -> bool:
        return (self._self_test_port is not None
                and remote.port == self._self_test_port
                and remote.is_loopback)

    # -- connect results ----------------------------------------------------

    def _from_connect_result(self, event: RawEvent) -> NetworkObservation | None:
        """A `connect()` return value, with no addressing of its own.

        Carries the errno and the process, and nothing else -- the syscall
        tracepoint cannot supply an address (KF-45). It is emitted so that a
        correlator can pair an outcome with the attempt that preceded it, and
        so that a failure which never reached SYN_SENT is still visible.
        """
        raw = event.fields.get("ret")
        if raw is None:
            self.stats.unusable_fields += 1
            return None
        try:
            value = int(raw, 16) if raw.startswith("0x") else int(raw)
        except ValueError:
            self.stats.unusable_fields += 1
            return None
        # Kernel returns are printed unsigned; fold to a signed errno.
        if value >= 1 << 63:
            value -= 1 << 64
        if value > 0:
            value = 0                    # a success return, not an errno
        return NetworkObservation(
            observation_id=self._next_id(),
            operation=NetworkOperation.CONNECT_RESULT,
            transport=Transport.TCP, direction=Direction.OUTBOUND,
            process=ProcessRef(pid=event.pid, tgid=event.pid,
                               comm=event.comm[:64],
                               pid_namespace=self._pid_namespace,
                               confidence=AttributionConfidence.PID_ONLY),
            local=None, remote=None, observed_at=self._when(event),
            sensor_id=self._sensor_id, outcome=outcome_for_errno(value),
            errno=value, socket_semantic=SocketSemantic.CONNECT_INITIATOR,
            destination_semantic="not_applicable")
