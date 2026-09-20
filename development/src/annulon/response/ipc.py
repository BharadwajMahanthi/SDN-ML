"""Authenticated local IPC between the unprivileged core and the broker.

Each constraint here answers a specific way this boundary gets broken.

* **Unix domain socket, never TCP on loopback.** A loopback port is reachable
  by every local process and carries no identity, so a broker behind one
  authorizes whoever connects first. A Unix socket carries peer credentials,
  which means the broker learns the caller's uid and pid from the *kernel*
  rather than from anything the caller said about itself.
* **Filesystem permissions are necessary but not sufficient.** A 0660 socket
  in a 0750 directory narrows who can connect; it does not establish who
  did. Both are used, and the credential check is the one that decides.
* **The caller's identity comes from the transport, not the payload.** A
  request body naming its own sender is a claim. ``SO_PEERCRED`` is evidence.
  Nothing in this module reads an identity out of a message.
* **Length-prefixed JSON with a hard cap.** No pickle and no arbitrary
  deserialisation, and a message that *declares* itself enormous is refused
  before a single byte of its body is read.

Linux is the deployment target and uses ``SO_PEERCRED``. macOS is supported
because development happens there, via ``LOCAL_PEERCRED``/``LOCAL_PEERPID``;
it is not a deployment platform. Anywhere else, credential lookup raises
rather than returning a guess, and the broker refuses the connection.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
from dataclasses import dataclass

__all__ = [
    "PeerCredentials", "IpcError", "MessageTooLarge", "PeerIdentityUnavailable",
    "MAX_MESSAGE_BYTES", "MAX_JSON_DEPTH", "read_message", "write_message",
    "peer_credentials", "peer_credentials_supported", "bind_listener",
    "connect", "SOCKET_MODE", "DIRECTORY_MODE",
]

#: 64 KiB. Comfortably above any legitimate request -- the largest one this
#: contract can express is a few hundred bytes -- and small enough that a
#: hostile sender cannot make the broker allocate meaningfully.
MAX_MESSAGE_BYTES = 64 * 1024
#: Nesting beyond this is refused. ``json`` recurses while parsing, so a
#: deeply nested document is a stack-exhaustion primitive; the contract's
#: deepest legitimate structure is three levels.
MAX_JSON_DEPTH = 8
#: The socket is readable and writable by owner and group only. The group is
#: the mechanism by which exactly one unprivileged core account is allowed to
#: reach a root-owned broker.
SOCKET_MODE = 0o660
DIRECTORY_MODE = 0o750

_LENGTH = struct.Struct("!I")
_LINUX_PEERCRED = struct.Struct("3i")            # pid, uid, gid
_SOL_LOCAL, _LOCAL_PEERCRED, _LOCAL_PEERPID = 0, 1, 2
_XUCRED_HEAD = struct.Struct("IIh")              # version, uid, ngroups
_XUCRED_SIZE = 4 + 4 + 2 + 2 + 16 * 4            # + padding + groups[16]


class IpcError(Exception):
    """The message could not be read, or is not usable as one."""


class MessageTooLarge(IpcError):
    """A declared length beyond the cap. Refused before the body is read."""


class PeerIdentityUnavailable(IpcError):
    """The kernel will not say who the caller is.

    Raised rather than defaulted. A broker that cannot identify its callers
    has no boundary to enforce, so this is fatal to the connection.
    """


@dataclass(frozen=True)
class PeerCredentials:
    """Who is on the other end of the socket, according to the kernel."""

    pid: int
    uid: int
    gid: int

    def __str__(self) -> str:
        return f"uid={self.uid} gid={self.gid} pid={self.pid}"


def peer_credentials_supported() -> bool:
    """Whether this platform can identify a local peer at all."""
    return sys.platform.startswith("linux") or sys.platform == "darwin"


def peer_credentials(connection: socket.socket) -> PeerCredentials:
    """Read the connected peer's credentials from the kernel.

    The returned uid is the value the kernel recorded for the peer process,
    not a value the peer transmitted, which is the entire point.
    """
    if sys.platform.startswith("linux"):
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                    _LINUX_PEERCRED.size)
        pid, uid, gid = _LINUX_PEERCRED.unpack(raw)
        return PeerCredentials(pid=pid, uid=uid, gid=gid)
    if sys.platform == "darwin":
        try:
            raw = connection.getsockopt(_SOL_LOCAL, _LOCAL_PEERCRED, _XUCRED_SIZE)
            _version, uid, ngroups = _XUCRED_HEAD.unpack(raw[:10])
            # groups[] starts after two bytes of alignment padding; group 0 is
            # the peer's effective gid.
            gid = struct.unpack("I", raw[12:16])[0] if ngroups > 0 else -1
            pid = struct.unpack(
                "i", connection.getsockopt(_SOL_LOCAL, _LOCAL_PEERPID, 4))[0]
        except (OSError, struct.error) as exc:
            raise PeerIdentityUnavailable(
                f"LOCAL_PEERCRED failed: {exc}") from exc
        return PeerCredentials(pid=pid, uid=uid, gid=gid)
    raise PeerIdentityUnavailable(
        f"no peer credential mechanism on {sys.platform!r}: the caller's "
        f"identity cannot be established, so the connection is refused")


def bind_listener(path: str, *, backlog: int = 8) -> socket.socket:
    """Create the broker's listening socket with restrictive permissions.

    The socket is created with a restrictive umask and chmod'ed before it is
    listened on, so there is no window in which it is world-writable. A stale
    socket file from a previous run is removed; a *live* one is not, because
    unlinking it would silently steal another broker's endpoint.
    """
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=DIRECTORY_MODE, exist_ok=True)
    if os.path.exists(path):
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.connect(path)
        except OSError:
            os.unlink(path)              # stale: nothing is listening
        else:
            probe.close()
            raise IpcError(f"a broker is already listening on {path}")
        finally:
            probe.close()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    previous = os.umask(0o177)
    try:
        listener.bind(path)
    finally:
        os.umask(previous)
    os.chmod(path, SOCKET_MODE)
    listener.listen(backlog)
    return listener


def connect(path: str, *, timeout: float = 5.0) -> socket.socket:
    """Open a client connection to the broker."""
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    client.connect(path)
    return client


def write_message(connection: socket.socket, payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True,
                      allow_nan=False).encode("utf-8")
    if len(body) > MAX_MESSAGE_BYTES:
        raise MessageTooLarge(f"{len(body)} bytes exceeds the {MAX_MESSAGE_BYTES} cap")
    connection.sendall(_LENGTH.pack(len(body)) + body)


def read_message(connection: socket.socket, *,
                 max_bytes: int = MAX_MESSAGE_BYTES) -> dict:
    """Read exactly one length-prefixed JSON object.

    The declared length is validated *before* the body is read, so a sender
    cannot make the broker wait on, or allocate for, a message it would
    reject anyway.
    """
    (length,) = _LENGTH.unpack(_recv_exactly(connection, _LENGTH.size))
    if length == 0:
        raise IpcError("empty message")
    if length > max_bytes:
        raise MessageTooLarge(f"declared {length} bytes, cap is {max_bytes}")
    body = _recv_exactly(connection, length)
    try:
        # ``json`` accepts the non-standard tokens NaN, Infinity and
        # -Infinity by default. They are not JSON, nothing in this contract
        # can represent them, and a float that compares false against itself
        # has no business inside a privileged decision. Rejected outright.
        payload = json.loads(body.decode("utf-8"),
                             parse_constant=_reject_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise IpcError(f"undecodable message: {type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        raise IpcError("message must be a JSON object")
    _check_depth(payload)
    return payload


def _reject_constant(name: str) -> None:
    raise ValueError(f"non-standard JSON constant {name!r}")


def _check_depth(value: object, depth: int = 1) -> None:
    if depth > MAX_JSON_DEPTH:
        raise IpcError(f"message nested deeper than {MAX_JSON_DEPTH} levels")
    if isinstance(value, dict):
        for item in value.values():
            _check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_depth(item, depth + 1)


def _recv_exactly(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        try:
            chunk = connection.recv(remaining)
        except (TimeoutError, socket.timeout) as exc:
            raise IpcError("timed out mid-message") from exc
        except OSError as exc:
            raise IpcError(f"socket error mid-message: {exc}") from exc
        if not chunk:
            raise IpcError("connection closed mid-message")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
