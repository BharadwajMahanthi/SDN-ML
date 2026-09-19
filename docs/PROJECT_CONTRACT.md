# PROJECT CONTRACT

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

## Acceptance requirements

Every important claim carries a status. Numerical targets are proposed until
approved and are never reported as measurements. Independent qualified review
of security-critical assumptions is required before production and is
currently NOT PERFORMED.
