"""Map existing SDN observations onto the shared V2 event envelope.

Deliberately the smallest possible adapter. `HostObservation`, `HostTable`,
the topology registries and the detectors are untouched: V2 §16 asks for a
mapper, not a rewrite, and the SDN regression tests must stay green.

The interesting part is the identity mapping. SDN identity is
``(datapath id, port)``, which has no meaning on a plain Linux host, so it
becomes an `EntityRef` whose *namespace* carries the network scope:

    sdn_port[net=lab]:00:00:aa:bb:cc:dd:ee:ff/1

A host-side consumer can correlate on the attachment without knowing what a
DPID is, which is exactly the property V2 §8 asks for.
"""

from __future__ import annotations

from datetime import datetime

from annulon.events import (
    CollectionQuality,
    DataClassification,
    Event,
    QualityFlag,
)
from annulon.identity import EntityKind, EntityRef
from sdnguard.domain.host import HostObservation
from sdnguard.domain.identity import DatapathId, PortIdentity

__all__ = ["SDN_SENSOR", "port_ref", "switch_ref", "attachment_ref",
           "observation_to_event"]

SDN_SENSOR = "sdnguard.openflow"


def switch_ref(dpid: DatapathId, network: str = "") -> EntityRef:
    return EntityRef(EntityKind.SDN_SWITCH, f"net={network}" if network else "",
                     str(dpid))


def port_ref(port: PortIdentity, network: str = "") -> EntityRef:
    return EntityRef(EntityKind.SDN_PORT, f"net={network}" if network else "",
                     str(port))


def attachment_ref(observation: HostObservation, network: str = "") -> EntityRef:
    """A MAC observed at a port. Named an *attachment* rather than a host,
    because that is all the network layer actually witnessed -- the MAC is an
    observation, not an identity (ADR-007)."""
    return EntityRef(EntityKind.SDN_ATTACHMENT,
                     f"net={network}" if network else "",
                     f"{observation.mac}@{observation.port}")


def observation_to_event(observation: HostObservation, *, event_id: str,
                         sequence: int, received_time: datetime,
                         sensor_version: str = "0.1",
                         network: str = "",
                         generation: int | None = None,
                         quality: CollectionQuality | None = None) -> Event:
    """One SDN observation as a common event.

    Addresses are ``INTERNAL`` rather than ``SENSITIVE``: a lab MAC and IP are
    topology metadata. No frame payload is carried -- the envelope references
    what was seen, never the bytes.
    """
    attributes: dict = {
        "mac": str(observation.mac),
        "ingress_port": str(observation.port),
        "datapath_id": observation.port.datapath_id.hex,
        "source": observation.source,
        "broadcast": observation.is_broadcast,
    }
    if observation.ip is not None:
        attributes["ip"] = str(observation.ip)
    if generation is not None:
        # The connection generation travels with the event so a consumer can
        # reject evidence from a superseded switch session (ADR-011).
        attributes["connection_generation"] = generation

    return Event(
        event_id=event_id,
        event_type="sdn.host.observation",
        sensor=SDN_SENSOR,
        sensor_version=sensor_version,
        sequence=sequence,
        observed_time=observation.observed_at,
        received_time=received_time,
        entity_refs=(
            attachment_ref(observation, network),
            port_ref(observation.port, network),
            switch_ref(observation.port.datapath_id, network),
        ),
        attributes=attributes,
        data_classification=DataClassification.INTERNAL,
        quality=quality or CollectionQuality(flags=(QualityFlag.OK,)),
    )
