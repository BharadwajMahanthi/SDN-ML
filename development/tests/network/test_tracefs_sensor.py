"""The tracefs sensor's parser and health reporting, attacked.

The parser is a trust boundary: it consumes kernel text that includes formats
it was not written for, lines truncated by a full buffer, and process names
chosen by whoever started the process. A parser that raises on an unexpected
line stops the sensor watching during exactly the noisy moment that matters.

The health reporting is the other half. Its job is to make the difference
between "nothing happened" and "we stopped being able to see" impossible to
miss, so most of these tests are about refusing to claim completeness.
"""

from __future__ import annotations

import pytest

from annulon.network.tracefs import (
    LossCounters, RawEvent, TracefsNetworkSensor, TracefsUnavailable,
    parse_trace_line,
)

ENTER = "   python3-84870   [006] ..... 53428.750752: sys_connect(fd: 6, uservaddr: ffffda4bd498, addrlen: 10)"
EXIT = "   python3-84870   [006] ..... 53428.750857: sys_connect -> 0xffffffffffffff8d"
STATE = ("   python3-84870   [006] ..s1. 53428.750851: inet_sock_set_state: "
         "family=AF_INET protocol=IPPROTO_TCP sport=44579 dport=60296 "
         "saddr=127.0.0.1 daddr=127.0.0.1")


# --- the parser -------------------------------------------------------------

def test_syscall_entry_and_exit_are_distinguished():
    """tracefs prints both as `sys_connect`.

    Only the shape of the line separates them: `(args)` for entry, `-> ret`
    for exit. Merging the two would fuse an attempt with its result and lose
    the distinction the whole contract is built around.
    """
    assert parse_trace_line(ENTER).kind == "sys_enter_connect"
    assert parse_trace_line(EXIT).kind == "sys_exit_connect"
    assert parse_trace_line(EXIT).fields["ret"] == "0xffffffffffffff8d"
    assert "ret" not in parse_trace_line(ENTER).fields


def test_softirq_context_is_detected():
    """`..s1.` means the process context is not the responsible process."""
    state = parse_trace_line(STATE)
    assert state.in_softirq
    assert not state.attributable
    assert parse_trace_line(ENTER).attributable


def test_state_transition_fields_are_extracted():
    fields = parse_trace_line(STATE).fields
    assert fields["family"] == "AF_INET"
    assert fields["sport"] == "44579"
    assert fields["daddr"] == "127.0.0.1"


@pytest.mark.parametrize("comm", [
    "my-weird-name", "a b c", "kworker/u16:3", "python3.12", "x" * 40,
    "systemd-resolve", "-leading-hyphen",
])
def test_a_comm_containing_hyphens_or_spaces_still_parses(comm):
    """The PID is anchored from the right, because a process name is chosen
    by whoever started it and may contain the separator."""
    line = f"   {comm}-4242   [003] ..... 1.234567: sys_connect -> 0x0"
    event = parse_trace_line(line)
    assert event is not None, comm
    assert event.pid == 4242
    assert event.comm == comm.strip()


@pytest.mark.parametrize("line", [
    "", "   ", "\n", "#", "# comment", "garbage", "no-pid [001] x",
    "python3-notanumber [006] ..... 1.0: sys_connect -> 0x0",
    "python3-84870 [notacpu] ..... 1.0: sys_connect -> 0x0",
    "python3-84870 [006] ..... notatime: sys_connect -> 0x0",
    "CPU:0 [LOST 1234 EVENTS]",
    "\x00\x01\x02", "python3-84870" + "x" * 100_000,
    None, 42, [], {},
])
def test_an_unrecognised_line_yields_none_rather_than_raising(line):
    """A sensor that dies on an unexpected line stops watching.

    tracefs interleaves comments, lost-event notices and formats this parser
    does not know about; none of them are worth losing visibility over.
    """
    assert parse_trace_line(line) is None


def test_a_truncated_line_does_not_raise():
    """What a full ring buffer produces."""
    for cut in range(1, len(STATE)):
        parse_trace_line(STATE[:cut])       # must not raise


# --- loss accounting --------------------------------------------------------

def test_any_loss_makes_the_sensor_stop_claiming_completeness():
    for counters in (LossCounters(overrun=1), LossCounters(commit_overrun=1),
                     LossCounters(dropped=1), LossCounters(queue_dropped=1)):
        assert not counters.lossless
        assert counters.total >= 1


def test_no_loss_is_lossless():
    """The positive control: a sensor that can never attest completeness is
    as useless as one that always does."""
    assert LossCounters().lossless
    assert LossCounters().total == 0


def test_kernel_loss_and_queue_loss_are_reported_separately():
    """They have different fixes: one is a buffer size, the other is a slow
    consumer, and an operator needs to know which."""
    counters = LossCounters(overrun=7, queue_dropped=3)
    body = counters.to_dict()
    assert body["overrun"] == 7
    assert body["queue_dropped"] == 3
    assert body["total"] == 10


# --- health -----------------------------------------------------------------

def test_a_sensor_that_never_started_does_not_attest_completeness():
    """Health must never be true merely because an object exists."""
    sensor = TracefsNetworkSensor()
    health = sensor.health()
    assert not health["running"]
    assert not health["attests_completeness"]
    assert any("reader thread" in reason for reason in health["degraded_reasons"])


def test_health_publishes_the_limitations_rather_than_burying_them():
    """Every one of these was measured, and each would otherwise be an
    assumption a consumer makes silently."""
    limitations = TracefsNetworkSensor().health()["known_limitations"]
    assert "namespace" in limitations["pid_namespace"]
    assert "correlation" in limitations["process_start_time"]
    assert "softirq" in limitations["softirq_context"]
    assert "not a" in limitations["pre_existing_connections"]
    assert limitations["udp"] == "not covered by these probes"


def test_the_capability_is_named_not_generic():
    """Doctrine §41: a weaker collector may never wear a stronger name."""
    assert TracefsNetworkSensor.capability == "NETWORK_TELEMETRY_TRACEFS"


def test_missing_requirements_are_named_precisely(monkeypatch):
    """"Unavailable" is not an answer an operator can act on; which
    tracepoint is missing determines whether the fix is a mount, a kernel
    config or a different machine."""
    from pathlib import Path
    monkeypatch.setattr(TracefsNetworkSensor, "_locate_tracefs",
                        staticmethod(lambda: (_ for _ in ()).throw(
                            TracefsUnavailable("tracefs is not mounted"))))
    assert not TracefsNetworkSensor.available()
    reasons = TracefsNetworkSensor.missing_requirements()
    assert reasons and "not mounted" in reasons[0]


def test_starting_without_the_required_tracepoints_raises(monkeypatch, tmp_path):
    """Never a silent downgrade to a weaker collector."""
    (tmp_path / "events").mkdir()
    monkeypatch.setattr(TracefsNetworkSensor, "_locate_tracefs",
                        staticmethod(lambda: tmp_path))
    sensor = TracefsNetworkSensor(root=tmp_path)
    with pytest.raises(TracefsUnavailable, match="cannot support"):
        sensor.start()


# --- bounded queue ----------------------------------------------------------

def test_the_queue_is_bounded_and_drops_are_counted():
    """Unbounded would let a traffic burst kill the security agent, which is
    a denial of service reachable by anyone who can open sockets."""
    sensor = TracefsNetworkSensor(queue_limit=10)
    for index in range(100):
        event = RawEvent(kind="sys_enter_connect", comm="x", pid=index, cpu=0,
                         timestamp=float(index), flags=".....")
        with sensor._lock:
            if len(sensor._queue) >= sensor._queue_limit:
                sensor._queue_dropped += 1
            else:
                sensor._queue.append(event)
    assert sensor.pending == 10
    assert sensor._queue_dropped == 90
    assert not sensor.loss().lossless


def test_draining_respects_a_limit_and_preserves_order():
    sensor = TracefsNetworkSensor()
    for index in range(5):
        sensor._queue.append(RawEvent("sys_enter_connect", "x", index, 0,
                                      float(index), "....."))
    first = sensor.drain(limit=2)
    assert [e.pid for e in first] == [0, 1]
    assert [e.pid for e in sensor.drain()] == [2, 3, 4]
    assert sensor.pending == 0


# --- an unparsed line is a hole in the observation (KF-63) ------------------

def test_an_unparsed_line_breaks_the_completeness_attestation():
    """A line that should have been an event and was not is a lost
    observation, and the sensor must stop attesting completeness.

    `attests_completeness` was `running and loss.lossless and not
    reader_error`, with `_unparsed` reported in the very same dict and
    excluded from the boolean -- so events lost to parse failure rendered as
    a complete, attested observation. The docstring above `health()` claimed
    it was "false whenever anything was lost".
    """
    from annulon.network.tracefs import TracefsNetworkSensor

    sensor = TracefsNetworkSensor.__new__(TracefsNetworkSensor)
    health = _health_with(sensor, unparsed=0)
    assert health["attests_completeness"] is True

    health = _health_with(sensor, unparsed=3)
    assert health["attests_completeness"] is False
    assert any("could not be parsed" in r for r in health["degraded_reasons"])


def _health_with(sensor, *, unparsed: int) -> dict:
    """Drive `health()` with a live-looking reader and a chosen loss count."""
    import threading

    from annulon.network.tracefs import LossCounters

    sensor._unparsed = unparsed
    sensor._reader_error = None
    sensor._started_at = None
    sensor._enabled_events = []
    sensor._queue = []
    sensor._lock = threading.Lock()
    sensor.sensor_id = "s"
    sensor.capability = "c"
    sensor._thread = threading.current_thread()
    sensor.loss = lambda: LossCounters(0, 0, 0, 0)
    return sensor.health()


@pytest.mark.parametrize("line", [
    "", "   ", "# tracer: nop",
    "#  TASK-PID  CPU#  ||||  TIMESTAMP  FUNCTION",
])
def test_tracefs_headers_are_not_counted_as_lost_observations(line):
    """The control that keeps the fix above from being useless.

    tracefs interleaves its own headers and blank lines with events. If
    those counted as unparsed, `attests_completeness` would be permanently
    false -- a check that cannot pass, which this project has already
    recorded as being no better than one that cannot fail (KF-56).
    """
    from annulon.network.tracefs import is_ignorable_trace_line

    assert is_ignorable_trace_line(line) is True


@pytest.mark.parametrize("line", [
    "garbage that matches no known format",
    "CPU:0 [LOST 9 EVENTS]",
    "nearly-an-event-but-not",
])
def test_an_unrecognised_event_line_is_counted(line):
    """Anything that is not a header and does not parse is a line that
    should have been an event. `[LOST n EVENTS]` especially: that is the
    kernel saying it dropped events."""
    from annulon.network.tracefs import is_ignorable_trace_line

    assert is_ignorable_trace_line(line) is False
