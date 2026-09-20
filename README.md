# Annulon

A local-first security agent for cloud Linux servers, built in Python.

**Status: engineering prototype.** Not production-ready, not independently
reviewed, and every claim below is scoped to what has actually been measured.
See `docs/CURRENT_STATE.md` for what is verified and what is not.

## What exists today

```
real Linux process
  -> netlink proc connector          kernel-pushed, no polling
  -> /proc enrichment                detail only, never discovery
  -> Annulon event                   domain-neutral envelope
  -> Evidence -> Finding -> Assessment
```

Physically evidenced on Ubuntu 24.04 with a passing negative control: the same
scenario with the sensor disabled produces zero events and zero findings.

The response boundary is under construction. A typed action contract and
broker-owned authorization policy exist and refuse a compromised core in unit
tests; nothing is physically enforced yet.

## Design commitments

The project is built around a small number of properties that are enforced by
tests rather than by convention:

- **A component may request an action; it may not authorize one.** There is no
  field in which a caller can claim permission, and no command string anywhere
  in the contract.
- **Severity and confidence are separate.** A finding may be catastrophic and
  barely supported, or certain and trivial. No single risk score exists.
- **Missing evidence is not negative evidence.** An unanswered probe is
  recorded as absence, never as proof that something did not happen.
- **Corroboration is checked by lineage.** Three detectors reading one event
  are one observation seen three ways, and the record says so.
- **A sensor must declare what it cannot see.** Measured: `/proc` polling
  missed 500 of 500 short-lived processes while reporting zero loss.
- **Nothing stays verified.** `tools/verify_all.py` re-checks every standing
  invariant; its first run found a defect in a shipped, tested module.

## Layout

```
development/src/annulon      the platform
development/src/sdnguard     SDN/OpenFlow integration, one optional pack
development/infra            reproducible Linux/OVS lab and experiments
development/tests            their tests
tools/                       context firewall, project memory, merge gate
docs/                        architecture, decisions, known failures, evidence
```

## Working on it

```bash
python -m pytest                      # the full suite
python tools/verify_all.py            # every standing invariant
python tools/merge_gate.py run --task <ID>
```

`AGENTS.md` is the canonical instruction file, shared by every agent and
human working here.

## Origin

Annulon began as an analysis of a Floodlight/TopoGuard SDN research prototype.
The concepts were recovered and reimplemented; the original Java tree is
preserved on the `legacy/java-topoguard-research` branch and is no longer part
of the product. `docs/LEGACY_CAPABILITY_MAP.md` and
`docs/LEGACY_SECURITY_MODEL.md` record what was learned from it and why
specific behaviours were rejected.

## Licence

See `LICENSE`.
