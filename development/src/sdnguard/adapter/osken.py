"""The real OS-Ken adapter.

This is the **only** module in the project permitted to import ``os_ken`` or
``eventlet`` (ADR-005, ADR-017). Everything it does is translation: framework
event in, domain value out. No security rule lives here, and no decision is
taken here.

Two deliberate choices:

* **Raw bytes, not the framework's dissector.** PacketIn payloads go to our
  own :mod:`sdnguard.adapter.normalize` parser rather than ``os_ken.lib.packet``.
  The parser is then the same code on the lab host and on a laptop, it is
  covered by local fuzzing, and a framework swap does not change how a frame
  is interpreted.
* **Connection generations.** OS-Ken hands out a ``Datapath`` object per
  connection. A reconnect produces a new one, and anything issued under the
  old connection must not be resolved by the new one, so each connection is
  numbered and the number travels with every event.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from os_ken.ofproto import ofproto_v1_3

from sdnguard.adapter.contract import (
    LinkObserved,
    PortChanged,
    PortStatus,
    SecurityCore,
    SendOutcome,
    SendResult,
    SwitchConnected,
    SwitchDisconnected,
)
from sdnguard.adapter.normalize import parse_ethernet, to_observation
from sdnguard.domain.events import ProbeRequest
from sdnguard.domain.identity import DatapathId, PortIdentity, PortNumber

__all__ = ["OsKenAdapter", "build_probe_frame"]

LOG = logging.getLogger("sdnguard.adapter.osken")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def build_probe_frame(probe: ProbeRequest, source_mac: bytes) -> bytes:
    """Build the wire frame for a liveness probe.

    An ARP request is used rather than ICMP (ADR-006): it is link-local, needs
    no routable controller address, and cannot be answered from off-segment.
    The probe's correlation id is *not* carried in the frame -- ARP has nowhere
    safe to put it -- so correlation is by (nonce known to us, probed port,
    probed MAC), which the probe manager enforces.
    """
    target_mac = probe.identity.mac.to_bytes()
    sender_ip = b"\x00\x00\x00\x00"
    target_ip = probe.identity.ip.packed if probe.identity.ip else b"\x00\x00\x00\x00"

    # Unicast to the host we are probing, so only that host may answer.
    ethernet_header = target_mac + source_mac + b"\x08\x06"
    arp_body = (
        b"\x00\x01"          # hardware type: ethernet
        b"\x08\x00"          # protocol type: ipv4
        b"\x06\x04"          # hlen, plen
        b"\x00\x01"          # opcode: request
        + source_mac + sender_ip
        + target_mac + target_ip
    )
    frame = ethernet_header + arp_body
    return frame.ljust(60, b"\x00")     # pad to the minimum ethernet frame


class OsKenAdapter(app_manager.OSKenApp):
    """Framework side of the adapter contract."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    #: Set by the launcher before the app starts; see ``run_controller.py``.
    security_core: SecurityCore | None = None
    probe_source_mac: bytes = b"\x02\xff\xff\xff\xff\xfe"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._datapaths: dict[int, Any] = {}
        self._generations: dict[int, int] = {}
        self._ports: dict[int, set[int]] = {}
        self.events_seen = 0

    # -- attachment ------------------------------------------------------

    def attach(self, core: SecurityCore) -> None:
        self.security_core = core

    def commands(self) -> "OsKenAdapter":
        return self

    def _emit(self, method: str, *args: Any) -> None:
        core = self.security_core
        if core is None:
            LOG.warning("event %s dropped: no security core attached", method)
            return
        self.events_seen += 1
        try:
            getattr(core, method)(*args)
        except Exception:
            # A defect in the core must not kill the OpenFlow connection: a
            # controller that disconnects on an unexpected event turns a bug
            # into a network outage. Log loudly and keep the channel alive.
            LOG.exception("security core raised handling %s", method)

    # -- lifecycle -------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _on_features(self, ev: Any) -> None:
        datapath = ev.msg.datapath
        dpid = datapath.id
        self._datapaths[dpid] = datapath
        self._generations[dpid] = self._generations.get(dpid, 0) + 1

        # Send every unmatched packet to the controller. Without this the
        # switch drops them in secure mode and no PacketIn ever arrives.
        parser, ofproto = datapath.ofproto_parser, datapath.ofproto
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=0,
            match=parser.OFPMatch(),
            instructions=[parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)])]))
        # Ask for the port inventory; the reply carries the real port numbers.
        datapath.send_msg(parser.OFPPortDescStatsRequest(datapath, 0))
        LOG.info("switch features: dpid=%016x generation=%d",
                 dpid, self._generations[dpid])

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def _on_port_desc(self, ev: Any) -> None:
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        numbers = sorted(p.port_no for p in ev.msg.body
                         if p.port_no <= ofproto.OFPP_MAX)
        self._ports[dpid] = set(numbers)
        ports = tuple(PortIdentity(DatapathId(dpid), PortNumber(n)) for n in numbers)
        self._emit("on_switch_connected",
                   SwitchConnected(DatapathId(dpid), ports, _now(),
                                   self._generations.get(dpid, 1)))
        LOG.info("port inventory: dpid=%016x ports=%s", dpid, numbers)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _on_state_change(self, ev: Any) -> None:
        datapath = ev.datapath
        dpid = getattr(datapath, "id", None)
        if dpid is None:
            return
        if ev.state == DEAD_DISPATCHER:
            self._datapaths.pop(dpid, None)
            self._ports.pop(dpid, None)
            self._emit("on_switch_disconnected",
                       SwitchDisconnected(DatapathId(dpid), _now(),
                                          self._generations.get(dpid, 1)))
            LOG.info("switch disconnected: dpid=%016x", dpid)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _on_port_status(self, ev: Any) -> None:
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        port = msg.desc
        if port.port_no > ofproto.OFPP_MAX:
            return

        if msg.reason == ofproto.OFPPR_ADD:
            status = PortStatus.ADDED
        elif msg.reason == ofproto.OFPPR_DELETE:
            status = PortStatus.REMOVED
        else:
            # OFPPR_MODIFY: link state lives in the port's state bitmap, not
            # in the reason code. OFPPS_LINK_DOWN is what "the cable went
            # away" actually looks like on the wire.
            down = bool(port.state & ofproto.OFPPS_LINK_DOWN)
            status = PortStatus.DOWN if down else PortStatus.UP

        identity = PortIdentity(DatapathId(datapath.id), PortNumber(port.port_no))
        self._emit("on_port_changed",
                   PortChanged(identity, status, _now(),
                               self._generations.get(datapath.id, 1)))
        LOG.info("port status: %s %s (reason=%d state=0x%x)",
                 identity, status.value, msg.reason, port.state)

    # -- packet in -------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _on_packet_in(self, ev: Any) -> None:
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        in_port = msg.match.get("in_port")
        if in_port is None or in_port > ofproto.OFPP_MAX:
            return

        frame = parse_ethernet(bytes(msg.data))
        if frame is None:
            return

        port = PortIdentity(DatapathId(datapath.id), PortNumber(in_port))
        generation = self._generations.get(datapath.id, 1)
        moment = _now()

        if frame.is_lldp:
            self._emit("on_link_observed",
                       LinkObserved(port, None, moment, generation))
            return

        observation = to_observation(frame, port, moment)
        if observation is None:
            return
        self._emit("on_host_observation", observation, generation)

    # -- SwitchCommands --------------------------------------------------

    def send_probe(self, probe: ProbeRequest, *, generation: int) -> SendResult:
        dpid = probe.target_port.datapath_id.value
        datapath = self._datapaths.get(dpid)
        if datapath is None:
            return SendResult.failed(SendOutcome.NO_SUCH_SWITCH,
                                     f"{probe.target_port.datapath_id}")
        if self._generations.get(dpid) != generation:
            return SendResult.failed(
                SendOutcome.STALE_GENERATION,
                f"probe issued under generation {generation}, switch is at "
                f"{self._generations.get(dpid)}")
        port_no = probe.target_port.port.value
        if port_no not in self._ports.get(dpid, set()):
            return SendResult.failed(SendOutcome.NO_SUCH_PORT, str(probe.target_port))

        parser, ofproto = datapath.ofproto_parser, datapath.ofproto
        data = build_probe_frame(probe, self.probe_source_mac)
        try:
            datapath.send_msg(parser.OFPPacketOut(
                datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=[parser.OFPActionOutput(port_no)], data=data))
        except Exception as exc:                       # transport-level failure
            return SendResult.failed(SendOutcome.TRANSPORT_ERROR, str(exc))
        LOG.info("probe %s sent out %s", probe.correlation_id[:8], probe.target_port)
        return SendResult.ok(f"probe {probe.correlation_id[:8]} out {probe.target_port}")

    def ports_of(self, dpid: DatapathId) -> tuple[PortIdentity, ...]:
        return tuple(PortIdentity(dpid, PortNumber(n))
                     for n in sorted(self._ports.get(dpid.value, set())))

    def is_connected(self, dpid: DatapathId) -> bool:
        return dpid.value in self._datapaths

    def generation_of(self, dpid: DatapathId) -> int:
        return self._generations.get(dpid.value, 0)
