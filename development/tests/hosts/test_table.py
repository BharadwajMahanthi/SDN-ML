"""Host table: learning, movement, out-of-order handling and bounds."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sdnguard.domain.host import (
    HostIdentity,
    HostObservation,
    IPAddress,
    MacAddress,
)
from sdnguard.domain.identity import InvalidIdentity, PortIdentity
from sdnguard.hosts.table import (
    HostTable,
    HostTableFull,
    ObservationEffect,
)

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
P1 = PortIdentity.of(0x0000AABBCCDDEEFF, 1)
P2 = PortIdentity.of(0x0000AABBCCDDEEFF, 2)
P3 = PortIdentity.of(0x0000AABBCCDDEEFF, 3)
MAC_A = MacAddress.parse("aa:bb:cc:dd:ee:01")
MAC_B = MacAddress.parse("aa:bb:cc:dd:ee:02")
IDENT_A = HostIdentity.of(MAC_A)


def obs(port=P1, at=T0, ident=IDENT_A, source="arp", broadcast=False):
    return HostObservation.of(ident, port, at, source, broadcast)


@pytest.fixture
def table() -> HostTable:
    return HostTable()


# -- learning --------------------------------------------------------------


def test_first_sighting_learns_the_host(table):
    result = table.observe(obs())
    assert result.effect is ObservationEffect.LEARNED
    assert result.previous_location is None
    assert table.location_of(MAC_A) == P1
    assert len(table) == 1


def test_broadcast_arp_learns_the_host(table):
    """Legacy returned before host learning on broadcast frames, so ARP --
    the main host announcement -- never populated the table (KF-09)."""
    result = table.observe(obs(broadcast=True))
    assert result.effect is ObservationEffect.LEARNED
    assert MAC_A in table


def test_same_port_later_refreshes(table):
    table.observe(obs())
    result = table.observe(obs(at=T0 + timedelta(seconds=10)))
    assert result.effect is ObservationEffect.REFRESHED
    assert result.record.primary.first_seen == T0
    assert result.record.primary.last_seen == T0 + timedelta(seconds=10)
    assert result.record.observation_count == 2


def test_learning_an_ip_enriches_the_identity(table):
    table.observe(obs())
    result = table.observe(obs(at=T0 + timedelta(seconds=1),
                               ident=HostIdentity.of(MAC_A, IPAddress.parse("10.0.0.1"))))
    assert result.effect is ObservationEffect.IDENTITY_ENRICHED
    assert result.record.identity.ip == IPAddress.parse("10.0.0.1")


# -- movement --------------------------------------------------------------


def test_a_second_port_is_an_additional_location_not_a_replacement(table):
    """A host at two ports at once is the central signal. Collapsing it --
    which the legacy table did by keying on MAC alone -- hides the hijack."""
    table.observe(obs())
    result = table.observe(obs(port=P2, at=T0 + timedelta(seconds=1)))
    assert result.effect is ObservationEffect.ADDITIONAL_LOCATION
    assert result.is_movement
    assert result.record.is_multi_homed
    assert result.record.concurrent_locations == 2
    assert result.record.port == P2, "most recent sighting is primary"
    assert result.previous_location.port == P1


def test_old_location_ages_out_and_the_move_becomes_plain(table):
    table.observe(obs())
    later = T0 + timedelta(minutes=10)      # beyond the 5 minute default TTL
    result = table.observe(obs(port=P2, at=later))
    assert result.effect is ObservationEffect.MOVED
    assert not result.record.is_multi_homed


def test_returning_to_a_known_port_reorders_rather_than_duplicates(table):
    table.observe(obs())
    table.observe(obs(port=P2, at=T0 + timedelta(seconds=1)))
    result = table.observe(obs(port=P1, at=T0 + timedelta(seconds=2)))
    assert result.record.concurrent_locations == 2
    assert result.record.port == P1
    assert result.effect is ObservationEffect.MOVED


def test_multi_homed_hosts_are_listable(table):
    table.observe(obs())
    table.observe(obs(port=P2, at=T0 + timedelta(seconds=1)))
    table.observe(obs(ident=HostIdentity.of(MAC_B), port=P3, at=T0))
    assert [r.mac for r in table.multi_homed()] == [MAC_A]


# -- out-of-order ----------------------------------------------------------


def test_a_late_observation_never_rewrites_history(table):
    """Silently reordering would let a delayed replay look like a fresh
    sighting."""
    table.observe(obs(at=T0 + timedelta(seconds=10)))
    result = table.observe(obs(at=T0))
    assert result.effect is ObservationEffect.LATE
    assert result.record.primary.last_seen == T0 + timedelta(seconds=10)
    assert result.record.observation_count == 1, "a late packet does not count"


def test_a_late_observation_on_another_port_does_not_create_a_move(table):
    table.observe(obs(at=T0 + timedelta(seconds=10)))
    result = table.observe(obs(port=P2, at=T0))
    assert result.effect is ObservationEffect.LATE
    assert not result.is_movement
    assert table.location_of(MAC_A) == P1


def test_duplicate_observations_are_idempotent_in_location(table):
    table.observe(obs())
    for _ in range(5):
        table.observe(obs(at=T0))
    record = table.get(MAC_A)
    assert record.concurrent_locations == 1
    assert record.primary.last_seen == T0


# -- bounds ----------------------------------------------------------------


def test_host_count_is_bounded_and_refuses_rather_than_evicting(table):
    """An attacker who can force eviction can flush a victim's record and
    erase the evidence of their own move."""
    small = HostTable(max_hosts=2)
    small.observe(obs())
    small.observe(obs(ident=HostIdentity.of(MAC_B)))
    with pytest.raises(HostTableFull, match="refusing rather than evicting"):
        small.observe(obs(ident=HostIdentity.of(MacAddress.parse("aa:bb:cc:dd:ee:03"))))
    assert len(small) == 2
    assert MAC_A in small, "the victim's record survives"


def test_locations_per_host_are_bounded(table):
    small = HostTable(max_locations=2, location_ttl=timedelta(hours=1))
    small.observe(obs(port=P1, at=T0))
    small.observe(obs(port=P2, at=T0 + timedelta(seconds=1)))
    small.observe(obs(port=P3, at=T0 + timedelta(seconds=2)))
    record = small.get(MAC_A)
    assert record.concurrent_locations == 2
    assert record.port == P3, "the newest sighting is always retained"


def test_limits_must_be_positive():
    for kwargs in ({"max_hosts": 0}, {"max_locations": 0},
                   {"location_ttl": timedelta(0)}):
        with pytest.raises(ValueError):
            HostTable(**kwargs)


def test_capacity_is_introspectable():
    assert HostTable(max_hosts=10, max_locations=3).capacity == (10, 3)


# -- maintenance -----------------------------------------------------------


def test_expire_drops_hosts_not_seen_within_the_ttl(table):
    table.observe(obs())
    assert table.expire(T0 + timedelta(minutes=1)) == 0
    assert table.expire(T0 + timedelta(minutes=10)) == 1
    assert len(table) == 0


def test_prune_locations_drops_stale_secondaries_only(table):
    table.observe(obs(port=P1, at=T0))
    table.observe(obs(port=P2, at=T0 + timedelta(seconds=1)))
    assert table.get(MAC_A).concurrent_locations == 2
    assert table.prune_locations(T0 + timedelta(minutes=10)) == 1
    record = table.get(MAC_A)
    assert record.concurrent_locations == 1
    assert record.port == P2, "the primary is never pruned"


def test_forget_port_removes_that_port_from_every_host(table):
    table.observe(obs(port=P1, at=T0))
    table.observe(obs(port=P2, at=T0 + timedelta(seconds=1)))
    table.observe(obs(ident=HostIdentity.of(MAC_B), port=P1, at=T0))
    assert table.forget_port(P1) == 2
    assert table.get(MAC_A).concurrent_locations == 1
    assert MAC_B not in table, "a host left with no location is forgotten"


def test_forget_removes_a_single_host(table):
    table.observe(obs())
    assert table.forget(MAC_A) is True
    assert table.forget(MAC_A) is False


def test_hosts_on_lists_every_host_at_a_port(table):
    table.observe(obs(port=P1, at=T0))
    table.observe(obs(ident=HostIdentity.of(MAC_B), port=P1, at=T0))
    assert [r.mac for r in table.hosts_on(P1)] == sorted([MAC_A, MAC_B])
    assert table.hosts_on(P3) == []


def test_observe_rejects_a_non_observation(table):
    with pytest.raises(InvalidIdentity):
        table.observe("not an observation")


def test_iteration_is_deterministic(table):
    table.observe(obs(ident=HostIdentity.of(MAC_B), port=P2, at=T0))
    table.observe(obs(port=P1, at=T0))
    assert [r.mac for r in table] == sorted([MAC_A, MAC_B])


def test_a_stored_record_always_has_at_least_one_location(table):
    """HostRecord tolerates a transient empty tuple during the move path, so
    the invariant is enforced where records actually enter the table."""
    import dataclasses

    from sdnguard.hosts.table import HostRecord

    table.observe(obs())
    empty = dataclasses.replace(table.get(MAC_A), locations=())
    with pytest.raises(InvalidIdentity, match="no location"):
        table._store(MAC_A, empty)
    assert table.get(MAC_A).concurrent_locations == 1, "table unchanged"


def test_every_observation_path_leaves_a_usable_primary(table):
    """Exercises learn, refresh, enrich, additional-location, aged-out move
    and late, asserting the primary is always addressable."""
    steps = [
        obs(port=P1, at=T0),
        obs(port=P1, at=T0 + timedelta(seconds=1)),
        obs(port=P1, at=T0 + timedelta(seconds=2),
            ident=HostIdentity.of(MAC_A, IPAddress.parse("10.0.0.1"))),
        obs(port=P2, at=T0 + timedelta(seconds=3)),
        obs(port=P3, at=T0 + timedelta(hours=1)),
        obs(port=P1, at=T0),
    ]
    for step in steps:
        result = table.observe(step)
        assert result.record.concurrent_locations >= 1
        assert result.record.primary.port is not None
