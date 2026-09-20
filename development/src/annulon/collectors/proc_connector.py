"""Linux netlink process connector.

The kernel's ``NETLINK_CONNECTOR`` / ``CN_IDX_PROC`` channel pushes
fork/exec/exit notifications to userspace. It is interesting for a
Python-first agent because it needs no compiler, no BPF toolchain and no
third-party package -- a raw socket and ``struct`` are enough.

What it gives: process lifecycle with PIDs, *pushed* by the kernel, so a
short-lived process cannot slip between polls.

What it does not give: argv, credentials or network activity. Those have to
come from elsewhere, and the evaluation must not pretend otherwise.

Wire format, from ``linux/connector.h`` and ``linux/cn_proc.h``::

    nlmsghdr   16 bytes   len, type, flags, seq, pid
    cn_msg     20 bytes   idx, val, seq, ack, len, flags
    proc_event 16 bytes   what, cpu, timestamp_ns
               + per-event payload
"""

from __future__ import annotations

import errno
import os
import select
import socket
import struct
from datetime import datetime, timezone
from typing import Iterator

from annulon.collectors.base import (
    HostSensor,
    SensorCapability,
    SensorHealth,
    SensorStats,
    SensorUnavailable,
)
from annulon.events import CollectionQuality, DataClassification, Event, QualityFlag
from annulon.identity import EntityKind, EntityRef

__all__ = ["ProcConnectorSensor", "NETLINK_CONNECTOR", "CN_IDX_PROC"]

NETLINK_CONNECTOR = 11
CN_IDX_PROC = 1
CN_VAL_PROC = 1
PROC_CN_MCAST_LISTEN = 1
PROC_CN_MCAST_IGNORE = 2

NLMSG_DONE = 3
_NLMSGHDR = struct.Struct("=IHHII")
_CN_MSG = struct.Struct("=IIIIHH")
_PROC_EVENT_HEAD = struct.Struct("=IIQ")

PROC_EVENT_FORK = 0x00000001
PROC_EVENT_EXEC = 0x00000002
PROC_EVENT_UID = 0x00000004
PROC_EVENT_GID = 0x00000040
PROC_EVENT_EXIT = 0x80000000

_WHAT_NAMES = {
    PROC_EVENT_FORK: "host.process.fork",
    PROC_EVENT_EXEC: "host.process.exec",
    PROC_EVENT_UID: "host.process.credential_change",
    PROC_EVENT_GID: "host.process.credential_change",
    PROC_EVENT_EXIT: "host.process.exit",
}


class ProcConnectorSensor:
    """Kernel-pushed process lifecycle events over netlink."""

    name = "proc_connector"
    version = "0.1"

    def __init__(self, *, host_id: str = "", boot_id: str = "",
                 recv_bytes: int = 1 << 16) -> None:
        self._socket: socket.socket | None = None
        self._stats = SensorStats()
        self._recv_bytes = recv_bytes
        self._detail = ""
        self.host_id = host_id or os.uname().nodename
        self.boot_id = boot_id or _read_boot_id()

    # -- interface -------------------------------------------------------

    def capabilities(self) -> frozenset[SensorCapability]:
        return frozenset({
            SensorCapability.PROCESS_EXEC,
            SensorCapability.PROCESS_EXIT,
            SensorCapability.PROCESS_FORK,
            SensorCapability.CREDENTIAL_CHANGE,
        })

    def requires_root(self) -> bool:
        return True          # CAP_NET_ADMIN to join the multicast group

    def preflight(self) -> tuple[bool, str]:
        if not hasattr(socket, "AF_NETLINK"):
            return False, "AF_NETLINK unavailable on this platform"
        try:
            probe = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM,
                                  NETLINK_CONNECTOR)
        except OSError as exc:
            return False, f"cannot open netlink socket: {exc}"
        try:
            probe.bind((0, CN_IDX_PROC))
        except OSError as exc:
            probe.close()
            if exc.errno in (errno.EPERM, errno.EACCES):
                return False, "binding CN_IDX_PROC needs CAP_NET_ADMIN"
            return False, f"cannot bind connector group: {exc}"
        probe.close()
        return True, "netlink connector available"

    def start(self) -> None:
        ok, detail = self.preflight()
        if not ok:
            raise SensorUnavailable(detail)
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM,
                             NETLINK_CONNECTOR)
        sock.bind((0, CN_IDX_PROC))
        # A large receive buffer is the difference between observing a burst
        # and silently dropping it. Loss is still counted, never hidden.
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
        except OSError:
            pass
        sock.setblocking(False)
        self._socket = sock
        self._subscribe(PROC_CN_MCAST_LISTEN)
        self._detail = "listening"

    def stop(self) -> None:
        if self._socket is not None:
            try:
                self._subscribe(PROC_CN_MCAST_IGNORE)
            except OSError:
                pass
            self._socket.close()
            self._socket = None
            self._detail = "stopped"

    def health(self) -> SensorHealth:
        return SensorHealth(
            running=self._socket is not None, detail=self._detail,
            stats=self._stats,
            # The kernel pushes every transition and signals ENOBUFS when it
            # drops, so absence is meaningful -- until a drop is recorded,
            # after which it is not.
            attests_completeness=self._stats.dropped == 0,
            blind_spot=("" if self._stats.dropped == 0
                        else f"{self._stats.dropped} kernel drop(s) recorded; "
                             "absence is no longer meaningful"))

    def events(self, timeout: float = 1.0) -> Iterator[Event]:
        if self._socket is None:
            return
        deadline_reached = False
        while not deadline_reached:
            ready, _, _ = select.select([self._socket], [], [], timeout)
            if not ready:
                return
            try:
                data = self._socket.recv(self._recv_bytes)
            except BlockingIOError:
                return
            except OSError as exc:
                if exc.errno == errno.ENOBUFS:
                    # The kernel told us it dropped messages. Record it: a gap
                    # the sensor knows about is far more useful than silence.
                    self._stats.dropped += 1
                    continue
                raise
            yield from self._parse(data)
            timeout = 0.0        # drain what is queued, then return

    # -- internals -------------------------------------------------------

    def _subscribe(self, operation: int) -> None:
        payload = struct.pack("=I", operation)
        cn = _CN_MSG.pack(CN_IDX_PROC, CN_VAL_PROC, 0, 0, len(payload), 0)
        body = cn + payload
        header = _NLMSGHDR.pack(_NLMSGHDR.size + len(body), NLMSG_DONE, 0, 0,
                                os.getpid())
        self._socket.send(header + body)

    def _parse(self, data: bytes) -> Iterator[Event]:
        offset = 0
        while offset + _NLMSGHDR.size <= len(data):
            length, _type, _flags, _seq, _pid = _NLMSGHDR.unpack_from(data, offset)
            if length < _NLMSGHDR.size or offset + length > len(data):
                self._stats.decode_errors += 1
                return
            body = offset + _NLMSGHDR.size
            if body + _CN_MSG.size + _PROC_EVENT_HEAD.size <= len(data):
                event = self._decode(data, body + _CN_MSG.size)
                if event is not None:
                    yield event
            offset += (length + 3) & ~3     # netlink messages are 4-byte aligned

    def _decode(self, data: bytes, offset: int) -> Event | None:
        try:
            what, cpu, timestamp_ns = _PROC_EVENT_HEAD.unpack_from(data, offset)
        except struct.error:
            self._stats.decode_errors += 1
            return None
        event_type = _WHAT_NAMES.get(what)
        if event_type is None:
            return None            # a kind we do not model; not an error
        payload = offset + _PROC_EVENT_HEAD.size
        attributes: dict = {"cpu": cpu, "kernel_timestamp_ns": timestamp_ns}
        try:
            if what == PROC_EVENT_EXEC:
                pid, tgid = struct.unpack_from("=ii", data, payload)
                attributes.update(pid=pid, tgid=tgid)
            elif what == PROC_EVENT_FORK:
                ppid, ptgid, cpid, ctgid = struct.unpack_from("=iiii", data, payload)
                attributes.update(parent_pid=ppid, parent_tgid=ptgid,
                                  pid=cpid, tgid=ctgid)
            elif what == PROC_EVENT_EXIT:
                pid, tgid, code, signal = struct.unpack_from("=iiII", data, payload)
                attributes.update(pid=pid, tgid=tgid, exit_code=code,
                                  exit_signal=signal)
            elif what in (PROC_EVENT_UID, PROC_EVENT_GID):
                pid, tgid, ruid, euid = struct.unpack_from("=iiII", data, payload)
                attributes.update(pid=pid, tgid=tgid, real_id=ruid, effective_id=euid)
        except struct.error:
            self._stats.decode_errors += 1
            return None

        self._stats.sequence += 1
        self._stats.emitted += 1
        now = datetime.now(timezone.utc)
        pid = attributes.get("pid", 0)
        return Event(
            event_id=f"pcn-{self._stats.sequence:016d}",
            event_type=event_type,
            sensor=self.name,
            sensor_version=self.version,
            sequence=self._stats.sequence,
            # The kernel timestamp is monotonic-since-boot, not wall clock, so
            # it is carried as an attribute and the wall time is recorded
            # separately rather than conflated.
            observed_time=now,
            received_time=now,
            entity_refs=(
                EntityRef(EntityKind.PROCESS_INSTANCE,
                          f"host={self.host_id};boot={self.boot_id}", str(pid)),
                EntityRef(EntityKind.HOST, "", self.host_id),
            ),
            attributes=attributes,
            data_classification=DataClassification.INTERNAL,
            quality=CollectionQuality(
                flags=(QualityFlag.EVENTS_DROPPED,) if self._stats.dropped
                else (QualityFlag.OK,),
                dropped_events=self._stats.dropped),
        )


def _read_boot_id() -> str:
    try:
        return open("/proc/sys/kernel/random/boot_id").read().strip()[:36]
    except OSError:
        return "unknown"
