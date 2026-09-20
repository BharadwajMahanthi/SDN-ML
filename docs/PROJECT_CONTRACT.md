# PROJECT CONTRACT

> **Superseded in scope by ADR-027 / PADMAVYUH_ARCHITECTURE_V2.md.** The
> objective below described the SDN product. The product is now a local-first
> agent for an ordinary Linux cloud server, with SDN as one optional pack.
> The engineering principles in this document continue to apply unchanged.

## Objective

Transform this Floodlight/TopoGuard research project into a Python-first,
real-time defensive network security platform with reproducible testing,
measurable security properties, and deployable artifacts.

Design philosophy: layered defence, controlled entry points, verification at
each layer, containment on failure, observability, recovery, minimal trust.
This is a design metaphor. The system is never described as impenetrable,
provably secure, or capable of detecting every attack.

## In scope

Python controller/application logic, detection, policy and enforcement,
feature extraction, model inference, APIs, automation, testing, an isolated
owner-approved AWS lab, and shared agent memory.

## Out of scope unless the owner records a decision

Scope reduction of the requested full port to a single detector. Replacing
the Java controller with a partial rewrite and calling it complete. New
OpenFlow protocol stacks or custom cryptography. Any hosted LLM in the
security decision path.

## Privacy rules

Hosted models orchestrate, architect, review and reason. Local tools read,
search, test, build and measure. Anything returned to a hosted model is
transmitted off this machine. Blocked material (credentials, keys, PCAPs,
private datasets, patent drafts, runtime journals) never goes to a hosted
model. Enforcement is `tools/context_policy.yaml`, not a prompt.

## Architecture boundaries

External native infrastructure — OVS, the kernel, cryptographic libraries —
is inventoried separately and is not made Python by wrapping it. Protocol
adapters are isolated from independently testable security logic. Packet
forwarding stays in the data plane. Slow work stays out of controller
callbacks.

## No artificial dead ends

A failed dependency, unavailable tool, disproven legacy assumption,
unsupported framework capability, or missing implementation does not
terminate development. Identify the underlying required capability, evaluate
alternatives, and implement the smallest safe replacement when necessary.
Block only the specific operation that genuinely requires unavailable owner
authority, external access, or irreversible action. Continue all independent
work. Never falsify evidence to preserve an existing design.

In practice:

- A tool name is not a requirement. "Run Mininet on macOS" is not the
  requirement; "a reproducible multi-host environment with isolated
  interfaces, a controllable datapath and observable packet paths" is.
- Before writing `BLOCKED`, perform an **ALTERNATIVE_ANALYSIS**: required
  capability, current approach, why it failed, alternatives with cost, risk
  and testability, recommended path. Then take the strongest safe path.
- Use `TASK_BLOCKED`, `EXTERNAL_ACTION_REQUIRED`, `ALTERNATIVE_SELECTED` or
  `DEFERRED_WITH_SAFE_PATH` rather than a project-wide stop.
- Frameworks are implementation details. OS-Ken is the current adapter, not
  the architecture. If it fails, isolate the missing capability and replace
  the smallest piece, behind the existing boundary.
- Anything we implement ourselves because no suitable library fits carries a
  higher test bar: specification, boundary, property, malformed-input,
  failure and resource-bound tests, plus fuzzing and golden fixtures for
  protocol-facing code. Do not trust custom infrastructure because we wrote it.
- Never reimplement cryptography, TLS, OS networking or a full TCP/IP stack
  without a narrow, documented necessity.
- A disproven research assumption is information, not failure. Record the
  evidence, mark the assumption rejected or conditional, and design something
  stronger. Never change the experiment to preserve the thesis.

## Acceptance requirements

Every important claim carries a status. Numerical targets are proposed until
approved and are never reported as measurements. Independent qualified review
of security-critical assumptions is required before production and is
currently NOT PERFORMED.
