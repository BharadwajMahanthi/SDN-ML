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

## Verification doctrine (permanent)

> **Annulon QA is adversarial verification, not confirmation testing. A
> security claim requires appropriate independent end-to-end evidence,
> negative controls, failure testing, and trust-boundary testing. Test count,
> line coverage, mocked behavior, command success, or absence of alerts are
> never sufficient by themselves. Every critical control must be tested
> against realistic bypasses and failure modes, and incomplete observation
> must never be interpreted as security success.**

The objective is not a passing suite. It is enough independent, adversarial,
reproducible evidence that a security property survives realistic failure,
hostile input, integration and deployment mistakes, concurrency, restart,
resource pressure and incorrect assumptions.

    DO NOT TEST THAT THE CODE CAN PASS.
    TRY TO MAKE THE SECURITY PROPERTY FAIL.

### Consequences that bind every campaign

- **A test count is never a security metric.** Report the *classes* of
  assurance a suite provides, and what remains untested. `1,513 tests passed`
  on its own is a statement about effort, not about security.
- **Unit tests cannot close a security requirement.** Every important
  property is attacked from several directions — unit, property, fuzz,
  mutation, contract, integration, fault injection, physical end-to-end.
- **Authorization suites must explore denial far harder than permission.**
  `valid request -> ALLOW` is one case; `almost-valid request -> DENY` is the
  work.
- **Do not mock what the claim is about.** If the claim is that nftables
  blocks real traffic, the closing evidence needs a real kernel and real
  packets.
- **The harness may never manufacture a result.** It establishes ground truth
  and measures externally; it never writes a finding, marks an action
  successful, or infers containment from broker output. Ground truth, system
  output and verification result stay structurally separate.
- **Negative controls are mandatory.** A positive experiment without one is
  incomplete evidence.
- **Completion is not success.** Experiment completion, observability
  completeness and security outcome are reported separately (ADR-029).
  "Nothing observed" is never "safe".
- **Never lower a requirement to pass.** Establish whether the test, the
  implementation, the architectural assumption or the environment is wrong,
  then fix that layer.
- **A flaky security test blocks its claim** until the nondeterminism is
  understood. Retries are diagnostic, never a way to manufacture a pass.
- **QA may reject architecture.** If an experiment shows an assumption is
  unreliable, the ADR changes — not the test.
- **Capability maturity is per-capability** (L0 code exists … L6 independent
  review). The product never inherits the level of its strongest component.

### Test lanes

    FAST      seconds/minutes   required every merge
    DEEP      fuzz/mutation     required before campaign close
    PHYSICAL  real kernel       required for any physical claim
    SOAK      hours             required before release maturity

`NOT_RUN` is never rendered as `PASS`.
