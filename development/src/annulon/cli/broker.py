"""The privileged broker as a runnable service.

Wiring only. Every decision this process makes is made by code that is
tested elsewhere; what lives here is argument parsing, configuration loading
and a shutdown path. That split matters because this is the privileged
process: a bug in an entry point should be an operational failure, not a
security one.

The configuration file is broker-owned. Nothing the core sends can change
where policy is read from, which backend is used, or which uid is treated as
the core — those are all decided before the socket is opened.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
from datetime import timedelta
from pathlib import Path

from annulon.response.broker import Broker, BrokerConfig, BrokerServer
from annulon.response.enforcement import Enforcer, UnavailableEnforcer
# Imported by module path rather than named in any string: this module is
# held to the privileged-action invariant, which is text-based precisely so
# that a command assembled as a literal is caught even where the call is
# indirect.
from annulon.response import nftables as _packet_filter
from annulon.response.policy import BrokerPolicy, PolicyError

__all__ = ["main", "build_server"]

DEFAULT_CONFIG = Path("/etc/annulon/broker.json")


def _load(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"broker configuration unreadable: {exc}")
    if not isinstance(raw, dict):
        raise SystemExit("broker configuration must be an object")
    return raw


#: Backends selectable from configuration, keyed by the backend's own
#: identifier rather than by a literal naming a privileged tool -- this
#: module is held to the privileged-action invariant like every other
#: non-backend module, and naming the tool here would breach it.
_BACKENDS = {
    _packet_filter.NftablesEnforcer.backend_id: _packet_filter.NftablesEnforcer,
    UnavailableEnforcer.backend_id: UnavailableEnforcer,
}

#: The backend chosen when configuration does not say. Derived from the
#: backend itself so this module names no privileged tool.
DEFAULT_BACKEND = _packet_filter.NftablesEnforcer.backend_id


def _enforcer(name: str) -> Enforcer:
    """Pick a backend by name, and refuse an unknown one.

    Falling back to a permissive default here would mean a typo in a config
    file silently produces a broker that authorises actions nothing carries
    out -- which reports success while the host is untouched.
    """
    factory = _BACKENDS.get(name)
    if factory is None:
        raise SystemExit(
            f"unknown enforcement backend {name!r}; "
            f"known: {sorted(_BACKENDS)}")
    try:
        return factory()
    except _packet_filter.NftablesUnavailable as exc:
        raise SystemExit(f"enforcement backend {name!r} unavailable: {exc}")


def build_server(config_path: Path) -> tuple[Broker, BrokerServer]:
    raw = _load(config_path)
    policy_path = raw.get("policy_file")
    if policy_path:
        try:
            policy = BrokerPolicy.load(Path(policy_path))
        except PolicyError as exc:
            # An unreadable policy yields a broker that denies, never one
            # that allows by default -- but starting at all with no policy
            # would hide the misconfiguration, so this is fatal.
            raise SystemExit(f"broker policy unusable: {exc}")
    else:
        policy = BrokerPolicy()

    callers = {}
    for uid, name in (raw.get("caller_uids") or {}).items():
        try:
            callers[int(uid)] = str(name)
        except (TypeError, ValueError):
            raise SystemExit(f"caller_uids key {uid!r} is not a uid")

    config = BrokerConfig(
        host_id=str(raw.get("host_id") or os.uname().nodename),
        boot_id=str(raw.get("boot_id") or _boot_id()),
        socket_path=str(raw.get("socket_path") or "/run/annulon/broker.sock"),
        journal_path=Path(raw.get("journal_path")
                          or "/var/lib/annulon/actions.jsonl"),
        caller_uids=callers,
        require_privilege=bool(raw.get("require_privilege", True)))

    broker = Broker(config, policy,
                    enforcer=_enforcer(str(raw.get("backend",
                                                       DEFAULT_BACKEND))))
    server = BrokerServer(broker, config,
                          sweep_interval=float(raw.get("sweep_seconds", 1.0)))
    return broker, server


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return "unknown-boot"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="annulon-broker", description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--check", action="store_true",
                        help="load the configuration and exit without serving")
    args = parser.parse_args(argv)

    broker, server = build_server(args.config)
    if args.check:
        print(json.dumps(broker.status(), indent=2, sort_keys=True))
        return 0

    server.start()
    # Reconcile before serving: state left by a previous process must be
    # accounted for before new actions are accepted (ADR-048).
    for note in broker.reconcile():
        print(f"[reconcile] {note}", file=sys.stderr)

    def _stop(_signum, _frame) -> None:
        server.stop()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        server.serve_forever()
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
