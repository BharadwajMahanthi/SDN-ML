"""SDN observations mapped onto the shared envelope, without a rewrite."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from annulon.events import DataClassification, DecodeOutcome, decode_event
from annulon.identity import EntityKind
from sdnguard.domain.host import HostIdentity, HostObservation, IPAddress, MacAddress
from sdnguard.domain.identity import PortIdentity
from sdnguard.v2.mapping import SDN_SENSOR, observation_to_event

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
PORT = PortIdentity.of(0x0000AABBCCDDEEFF, 1)
IDENT = HostIdentity.of(MacAddress.parse("02:00:00:00:00:01"),
                        IPAddress.parse("10.10.0.1"))
OBS = HostObservation.of(IDENT, PORT, T0, "arp", True)


def test_an_sdn_observation_becomes_a_common_event():
    event = observation_to_event(OBS, event_id="evt-sdn-0001", sequence=1,
                                 received_time=T0, network="lab")
    assert event.sensor == SDN_SENSOR
    assert event.event_type == "sdn.host.observation"
    outcome, decoded, _ = decode_event(event.to_json())
    assert outcome is DecodeOutcome.OK
    assert decoded.attributes["ingress_port"] == str(PORT)


def test_sdn_identity_becomes_a_namespaced_entity_ref():
    """A host-side consumer can correlate on the attachment without knowing
    what a DPID is."""
    event = observation_to_event(OBS, event_id="evt-sdn-0001", sequence=1,
                                 received_time=T0, network="lab")
    kinds = {r.kind for r in event.entity_refs}
    assert kinds == {EntityKind.SDN_ATTACHMENT, EntityKind.SDN_PORT,
                     EntityKind.SDN_SWITCH}
    for ref in event.entity_refs:
        assert ref.namespace == "net=lab"


def test_the_attachment_is_named_an_attachment_not_a_host():
    """The network layer witnessed a MAC at a port; that is not an identity."""
    event = observation_to_event(OBS, event_id="evt-sdn-0001", sequence=1,
                                 received_time=T0)
    attachment = next(r for r in event.entity_refs
                      if r.kind is EntityKind.SDN_ATTACHMENT)
    assert "@" in attachment.identifier
    assert EntityKind.HOST not in {r.kind for r in event.entity_refs}


def test_the_connection_generation_travels_with_the_event():
    event = observation_to_event(OBS, event_id="evt-sdn-0001", sequence=1,
                                 received_time=T0, generation=3)
    assert event.attributes["connection_generation"] == 3


def test_full_64_bit_datapath_ids_survive_the_mapping():
    port = PortIdentity.of(0xFFFFFFFFFFFFFFFF, 4)
    observation = HostObservation.of(IDENT, port, T0, "arp")
    event = observation_to_event(observation, event_id="evt-sdn-0002",
                                 sequence=2, received_time=T0)
    assert event.attributes["datapath_id"] == "ffffffffffffffff"
    _, decoded, _ = decode_event(event.to_json())
    assert decoded.attributes["datapath_id"] == "ffffffffffffffff"


def test_no_frame_payload_is_carried():
    """The envelope references what was seen, never the bytes."""
    event = observation_to_event(OBS, event_id="evt-sdn-0001", sequence=1,
                                 received_time=T0)
    assert event.data_classification is DataClassification.INTERNAL
    payload = json.loads(event.to_json())
    for forbidden in ("payload", "frame", "raw", "data"):
        assert forbidden not in payload["attributes"]


def test_the_event_stays_within_its_size_bound():
    event = observation_to_event(OBS, event_id="evt-sdn-0001", sequence=1,
                                 received_time=T0, network="lab")
    assert len(event.to_json().encode()) < 2048


def test_the_mapper_does_not_modify_the_observation():
    before = OBS.to_location()
    observation_to_event(OBS, event_id="evt-sdn-0001", sequence=1, received_time=T0)
    assert OBS.to_location() == before
