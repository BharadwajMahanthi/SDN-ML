"""Host sensor interface, and the completeness property V2-HOST-01 measured."""

from __future__ import annotations

import pytest

from annulon.collectors.base import (
    HostSensor,
    SensorCapability,
    SensorHealth,
    SensorStats,
)
from annulon.collectors.proc_connector import ProcConnectorSensor
from annulon.collectors.proc_poll import ProcPollSensor


@pytest.mark.parametrize("sensor", [ProcConnectorSensor(host_id="h", boot_id="b"),
                                    ProcPollSensor(host_id="h", boot_id="b")])
def test_candidates_satisfy_the_interface(sensor):
    assert isinstance(sensor, HostSensor)
    assert sensor.capabilities()
    assert isinstance(sensor.preflight(), tuple)


def test_preflight_refuses_rather_than_failing_later():
    """A candidate must say it cannot run before a caller starts trusting it."""
    ok, detail = ProcConnectorSensor(host_id="h", boot_id="b").preflight()
    assert isinstance(ok, bool) and detail


def test_polling_declares_that_it_cannot_attest_to_completeness():
    """The central V2-HOST-01 finding: a sensor missing 500 of 500 short-lived
    processes reported zero drops, because a counter only reports loss the
    sensor noticed."""
    health = ProcPollSensor(interval=0.1, host_id="h", boot_id="b").health()
    assert health.attests_completeness is False
    assert "never observed" in health.blind_spot
    assert not health.lossy, "it genuinely detected no loss -- that is the problem"
    assert not health.trustworthy_absence


def test_the_connector_attests_until_the_kernel_reports_a_drop():
    sensor = ProcConnectorSensor(host_id="h", boot_id="b")
    assert sensor.health().attests_completeness
    sensor._stats.dropped = 1
    health = sensor.health()
    assert not health.attests_completeness
    assert not health.trustworthy_absence
    assert "no longer meaningful" in health.blind_spot


def test_absence_is_only_meaningful_from_a_running_attesting_sensor():
    healthy = SensorHealth(running=True, stats=SensorStats())
    assert healthy.trustworthy_absence
    assert not SensorHealth(running=False).trustworthy_absence
    assert not SensorHealth(running=True,
                            stats=SensorStats(dropped=1)).trustworthy_absence
    assert not SensorHealth(running=True,
                            attests_completeness=False).trustworthy_absence


def test_the_two_candidates_have_genuinely_different_capabilities():
    """The comparison is a trade-off, not a ranking on one axis: the
    connector never misses a process, polling can read argv."""
    connector = ProcConnectorSensor(host_id="h", boot_id="b").capabilities()
    poll = ProcPollSensor(host_id="h", boot_id="b").capabilities()
    assert SensorCapability.PROCESS_ARGV in poll
    assert SensorCapability.PROCESS_ARGV not in connector
    assert SensorCapability.PROCESS_EXIT in connector
    assert SensorCapability.PROCESS_EXIT not in poll


def test_a_collector_decides_nothing():
    """A collector that filtered by suspiciousness would be a detector with
    no evidence trail."""
    for sensor in (ProcConnectorSensor(host_id="h", boot_id="b"),
                   ProcPollSensor(host_id="h", boot_id="b")):
        for forbidden in ("assess", "detect", "decide", "score", "classify"):
            assert not hasattr(sensor, forbidden)
