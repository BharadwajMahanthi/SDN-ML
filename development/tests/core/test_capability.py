"""Capability manifest: SUPPORTED must never imply ACTIVE AND HEALTHY."""

from __future__ import annotations

import json

import pytest

from annulon.capability import (
    AgentState,
    Capability,
    CapabilityManifest,
    Configuration,
    Health,
    PlatformProfile,
    Support,
)


def manifest() -> CapabilityManifest:
    return CapabilityManifest(PlatformProfile.LINUX_HOST, "0.1")


# -- the three axes stay separate ------------------------------------------


def test_only_supported_enabled_and_healthy_is_effective():
    c = Capability("host_process_events", Support.SUPPORTED,
                   Configuration.ENABLED, Health.HEALTHY)
    assert c.effective


@pytest.mark.parametrize(
    "support,configuration,health",
    [
        (Support.SUPPORTED, Configuration.NOT_CONFIGURED, Health.NOT_APPLICABLE),
        (Support.SUPPORTED, Configuration.DISABLED, Health.NOT_APPLICABLE),
        (Support.SUPPORTED, Configuration.ENABLED, Health.DEGRADED),
        (Support.SUPPORTED, Configuration.ENABLED, Health.FAILED),
        (Support.SUPPORTED, Configuration.ENABLED, Health.UNKNOWN),
        (Support.UNSUPPORTED_ON_PROFILE, Configuration.NOT_CONFIGURED, Health.NOT_APPLICABLE),
        (Support.NOT_IMPLEMENTED, Configuration.NOT_CONFIGURED, Health.NOT_APPLICABLE),
    ],
)
def test_nothing_else_counts_as_effective(support, configuration, health):
    assert not Capability("f", support, configuration, health).effective


def test_an_unsupported_feature_cannot_claim_health():
    """Saying an unsupported feature is healthy is the overclaim this model
    exists to prevent."""
    with pytest.raises(ValueError, match="meaningless"):
        Capability("sdn_topology", Support.UNSUPPORTED_ON_PROFILE,
                   Configuration.NOT_CONFIGURED, Health.HEALTHY)


def test_an_unconfigured_feature_cannot_be_healthy():
    with pytest.raises(ValueError, match="cannot be HEALTHY"):
        Capability("cloud_audit", Support.SUPPORTED,
                   Configuration.NOT_CONFIGURED, Health.HEALTHY)


# -- degradation -----------------------------------------------------------


def test_not_configured_is_a_choice_but_broken_is_a_degradation():
    m = manifest()
    m.declare(Capability("cloud_audit", Support.SUPPORTED,
                         Configuration.NOT_CONFIGURED, Health.NOT_APPLICABLE))
    assert m.state() is AgentState.HEALTHY, "an unconfigured optional source is not a fault"
    m.declare(Capability("host_process_events", Support.SUPPORTED,
                         Configuration.ENABLED, Health.FAILED))
    assert m.state() is AgentState.DEGRADED_COLLECTION
    assert m.degraded() == ["host_process_events"]


def test_health_can_change_at_runtime():
    m = manifest()
    m.declare(Capability("host_process_events", Support.SUPPORTED,
                         Configuration.ENABLED, Health.HEALTHY))
    assert m.covers("host_process_events")
    m.update_health("host_process_events", Health.DEGRADED, "sequence gaps")
    assert not m.covers("host_process_events")
    assert m.state() is AgentState.DEGRADED_COLLECTION


def test_states_without_inputs_are_not_fabricated():
    """Export health, policy expiry and enforcement availability have no
    sources in this build, so the manifest must not invent a conclusion."""
    m = manifest()
    m.declare(Capability("host_process_events", Support.SUPPORTED,
                         Configuration.ENABLED, Health.HEALTHY))
    assert m.state() in (AgentState.HEALTHY, AgentState.DEGRADED_COLLECTION)


# -- honest reporting ------------------------------------------------------


def test_an_absent_capability_is_never_covered():
    assert not manifest().covers("ai_security")


def test_sdn_is_unsupported_on_a_plain_linux_profile():
    m = manifest()
    m.declare(Capability("sdn_topology", Support.UNSUPPORTED_ON_PROFILE))
    assert not m.covers("sdn_topology")
    assert "sdn_topology" not in m.effective()


def test_the_manifest_reports_the_full_picture_not_a_boolean():
    m = manifest()
    m.declare(Capability("host_process_events", Support.SUPPORTED,
                         Configuration.ENABLED, Health.HEALTHY))
    m.declare(Capability("cloud_audit", Support.SUPPORTED,
                         Configuration.NOT_CONFIGURED, Health.NOT_APPLICABLE))
    m.declare(Capability("sdn_topology", Support.UNSUPPORTED_ON_PROFILE))
    payload = json.loads(m.to_json())
    by_name = {c["name"]: c for c in payload["capabilities"]}
    assert by_name["cloud_audit"]["support"] == "supported"
    assert by_name["cloud_audit"]["configuration"] == "not_configured"
    assert by_name["cloud_audit"]["effective"] is False
    assert payload["effective"] == ["host_process_events"]


# -- serialisation and forward compatibility -------------------------------


def test_manifest_round_trip():
    m = manifest()
    m.declare(Capability("host_process_events", Support.SUPPORTED,
                         Configuration.ENABLED, Health.HEALTHY))
    restored = CapabilityManifest.from_dict(json.loads(m.to_json()))
    assert restored.effective() == m.effective()
    assert restored.profile is PlatformProfile.LINUX_HOST


def test_an_unknown_profile_does_not_break_a_reader():
    restored = CapabilityManifest.from_dict(
        {"profile": "quantum_host", "agent_version": "9", "capabilities": []})
    assert restored.profile is PlatformProfile.UNKNOWN


def test_an_unknown_future_capability_decodes_without_improving_posture():
    restored = CapabilityManifest.from_dict({
        "profile": "linux_host", "agent_version": "9",
        "capabilities": [{"name": "time_travel", "support": "brand_new",
                          "configuration": "on", "health": "great"}]})
    assert not restored.covers("time_travel")
    assert restored.effective() == []


def test_an_inconsistent_entry_is_recorded_as_unknown_not_dropped():
    """A contradictory entry from a faulty producer must not silently
    improve the reported posture, and must not vanish either."""
    restored = CapabilityManifest.from_dict({
        "profile": "linux_host", "agent_version": "9",
        "capabilities": [{"name": "bogus", "support": "unsupported_on_profile",
                          "configuration": "enabled", "health": "healthy"}]})
    assert "bogus" in restored.capabilities
    assert not restored.covers("bogus")
    assert restored.capabilities["bogus"].health is Health.UNKNOWN
