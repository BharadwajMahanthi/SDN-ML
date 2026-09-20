# Padmavyuh v2 — Cloud Workload and AI Security Architecture

**Version:** 0.2-draft · **Date:** 2026-09-20  
**Status:** Proposed architecture; not an implementation certificate or production-readiness claim.  
**Implementation starting point:** The owner's reported SDNGuard Python prototype and P6 integration progress. The current repository and its evidence artifacts have not been independently inspected for this document.

## 1. Product definition and scope correction

Build an installable, local-first security agent for supported cloud servers, with an optional customer-controlled management service and additional application/AI/cloud integrations. SDN topology integrity is one optional protection pack, not the product's organizing assumption.

The minimum useful installation must work on an ordinary Linux VM without Floodlight, OpenFlow, OVS, Mininet, Kubernetes, an LLM, or a vendor-hosted inference service. It observes the operating system, detects specified behaviors, evaluates policy, and carries out only explicitly authorized, bounded responses. Applications do not have to use AI to benefit.

The broader system combines host runtime protection, cloud identity/configuration evidence, application authorization, AI-agent controls, and optional network-controller integrations. It does not promise visibility into every layer from a single agent.

**Primary objective:** reduce the impact of unauthorized state changes and actions while bounding false containment, service disruption, resource consumption, and disclosure of customer data.

**Security meaning of the Padmavyuh metaphor:** independent trust boundaries, multiple evidence sources, least privilege, constrained responses, protected evidence, and tested recovery. More components do not automatically mean more security.

## 2. Research basis and interpretation

### 2.1 Attached research source

Source B1 is *Certified Offensive AI Security Professional, Version 1*, EC-Council, supplied as `COASP-book.pdf` (1,002 PDF pages). Page references here are physical PDF page numbers, not the per-module page numbering printed on the pages.

Relevant sections were reviewed through targeted retrieval; this is not a claim that every example or every page was exhaustively audited.

| Book material | Design requirement derived from it |
|---|---|
| Module 1, p.30: AI-augmented techniques versus AI as the target | Separate conventional intrusion detection from protection of models, data and autonomous agents; do not claim to identify AI authorship from ordinary telemetry. |
| Module 1, pp.38–39: data, model, pipeline and infrastructure assets | Maintain an asset/dependency inventory across the complete protected workload. |
| Module 1, pp.93–95: defense in depth, zero trust, least agency, monitoring, supply chain and oversight | Separate sensing, reasoning, authorization and privileged execution. |
| Module 1, pp.108–109: Claim–Argument–Evidence assurance cases | Every release claim must name assumptions, code, tests and evidence. |
| Module 2, p.138: asset and attack-surface discovery | Inventory owned workloads and integrations before enabling detector claims. |
| Module 3, p.284: scanning and fuzzing | Test parser, API and behavioral assumptions, not only known signatures. |
| Modules 4–6: prompt risks, adversarial ML, privacy and poisoning; pp.368,491,568 and relevant sections | Add application-level mediation, protected retrieval, model admission, evaluation and provenance. |
| Module 7, pp.715–724: action-specific authorization, time-bound capabilities, cost/loop limits and external fail-safes | An AI model cannot authorize itself; action limits live in separately controlled code and credentials. |
| Module 8, pp.801–805: segmentation, secrets and component inventory | Protect runtime and delivery infrastructure; do not grant broad account permissions to each host agent. |
| Module 9, pp.843–848: test master plans, developmental/operational testing and statistical evaluation | Predeclare workloads, hypotheses, thresholds, negative controls and measurement methods. |
| Module 10, pp.936–939,950–951: tamper-resistant evidence, privacy and recovery | Use minimized protected evidence, explicit incident holds, verified restoration and post-incident validation. |

The book is a threat and defensive-principles reference, not a specification for a universal host agent. OS-specific collectors, distributed protocols, deployment boundaries and schemas below are proposed engineering additions.

**Source-quality rule:** verify concrete platform claims independently. For example, B1 p.804 describes Kubernetes Secrets as providing encrypted storage. Kubernetes' own documentation states that Secrets are unencrypted in etcd by default unless encryption at rest is configured [S09]. This architecture therefore requires verification of effective encryption rather than relying on the object name. Likewise, a hash or signature establishes a particular integrity/provenance property, not that the originating observation was true or the signed software was benign.

### 2.2 External technical basis

Use NIST zero-trust architecture for resource-centered authorization [S01], OWASP for application and AI action boundaries [S03–S05], the Tetragon documentation and threat model for Linux sensor feasibility and limits [S06–S07], SPIFFE for workload identity [S08], IETF RATS for attestation roles [S10], and TUF for update trust [S11]. These references guide design; none certifies this new implementation.

ATT&CK and ATLAS mappings must be pinned to reviewed versions. A mapping is a classification, not proof of coverage. Avoid copying inconsistent technique IDs from a training slide without checking their authoritative definitions.

## 3. Current implementation: preserve, qualify, extend

The owner reports a working chain:

`namespace host → veth → OVS kernel datapath → OpenFlow 1.3 → OS-Ken adapter → parser → HostObservation → HostTable`

This is valuable real software-datapath integration evidence. It is not evidence of a physical switch ASIC, complete attack detection, endpoint protection, or an entire cloud account being protected.

Preserve the existing pure domain types, temporal state machines, bounded probes, findings, observe-only policy, regression tests, lab harness and separated ground truth. Do not restart the project or delete the SDN implementation.

Specific follow-ups from the reported implementation:

- Keep OS-Ken/Eventlet inside a supervised optional SDN process. Import restrictions alone do not establish a process-wide concurrency boundary. Eventlet discourages new use [S13]; do not spread it to the host agent.
- Review KF-22 shutdown handling. `os._exit()` bypasses cleanup handlers and stdio flushing [S12]. Forced termination must be recorded distinctly, not silently treated as clean experiment success. Require a completion manifest, durable event drain and independent process/port cleanup evidence.
- Distinguish a stopped sensor, missing events and incomplete experiment from an attack-free run.
- Do not inherit SDN-specific identities or port-down assumptions into general host protection.
- Preserve provenance and required third-party license notices even when following an owner's preference not to add optional AI co-author trailers.

## 4. Supported deployment profiles

| Profile | Local mechanism | Intended coverage | Release policy |
|---|---|---|---|
| Linux VM on AWS, Azure, GCP or private infrastructure | Native sensor helper + Python core + optional broker | Host process/file/auth/network behavior | First supported product profile; certify exact distributions/kernels. |
| Linux Kubernetes worker | Node sensor plus workload/cgroup identity; separate Kubernetes connector | Host and pod behavior, approved cluster context | Later explicit profile, not automatically validated by VM tests. |
| Windows Server | Native event collectors and Windows Filtering Platform adapter [S14] | Windows-specific host/network coverage | Separate implementation, installer and tests. |
| macOS development/endpoint | Native supported APIs, including Endpoint Security where authorized [S15] | Explicitly documented endpoint capabilities | Optional; Linux collector is not portable merely because core code is Python. |
| Provider-managed/serverless workload | Supported extension/SDK/gateway plus cloud logs | Application/control-plane visibility | Reduced capability profile; no claim of full guest-kernel visibility. |
| Managed database or SaaS | Audit/API integration | Exposed service and identity events | Connector coverage only. |
| SDN infrastructure | Existing isolated OpenFlow adapter | Topology, host-location and flow-integrity protection | Optional pack; no dependency in ordinary server installation. |

Serverless extensions are not automatically independent trust boundaries. For example, Lambda documents shared permissions, credentials and environment variables between a function and its extensions [S16]. Compromise assumptions must reflect that.

Each installation emits a **capability manifest**. Every protection is `AVAILABLE`, `ACTIVE`, `DEGRADED`, `UNSUPPORTED`, `DISABLED_BY_POLICY` or `NOT_VALIDATED_ON_THIS_PLATFORM`. A running agent with an unavailable sensor must not display an unqualified green status.

## 5. Threat model and trust boundaries

### Adversary levels

A1: remote unauthenticated network/application client.  
A2: authenticated low-privilege user, application compromise or unprivileged container execution.  
A3: guest root/kernel-equivalent compromise.  
A4: cloud-account administrator, fleet-management or release-signing compromise.  
A5: hypervisor, firmware or hardware compromise.

The first production claim should target A1/A2 within tested telemetry and authorization boundaries. A3 requires independent off-host evidence and recovery; no same-kernel agent can be assumed to report truth against an adversary controlling that kernel [S07]. A4 requires separately controlled signing, cloud-organization restrictions and recovery authority. A5 requires platform-specific attestation/provider controls, not a Python promise [S10].

Protect these assets: workloads and data; user/service identities; cloud privileges; models and corpora; detection policy; action authority; evidence; software-update trust; system availability.

### Independent trust zones

1. Untrusted workload/application processes.
2. Native sensor/export service with restricted privileged access.
3. Unprivileged Python analysis process.
4. Small privileged response broker with its own authorization checks.
5. Customer-controlled management and evidence service.
6. Release-signing and emergency recovery authority, separated from normal runtime administration.
7. Optional AI models/tools, treated as untrusted proposers rather than authorities.

The local zones share a kernel. Their independence is meaningful against lower-privileged compromise, not an asserted defense against full kernel control.

## 6. End-to-end architecture

```text
                 CUSTOMER-OWNED CLOUD / PRIVATE ENVIRONMENT

 Ordinary server / container node          AI-enabled application (optional)
 ┌───────────────────────────────┐         ┌──────────────────────────────────┐
 │ Workloads                     │         │ Request + retrieval integration  │
 │ OS process/file/auth/network   │         │ LLM / agent                       │
 └──────────────┬────────────────┘         │ Typed tool authorization broker   │
                │ observations             └─────────────────┬────────────────┘
 ┌──────────────▼────────────────┐                           │ events
 │ Native sensor/export helper   │                           │
 │ Bounded capture and loss data │                           │
 └──────────────┬────────────────┘                           │
                │ local authenticated IPC                   │
 ┌──────────────▼────────────────────────────────────────────▼────────────┐
 │ Python security core                                                 │
 │ Validate → attribute identity → correlate → detect → policy proposal   │
 │ Local spool, sensor health, capability manifest, policy cache          │
 └──────────────┬────────────────────────────┬────────────────────────────┘
                │ typed action proposal     │ outbound mTLS
 ┌──────────────▼────────────────┐   ┌───────▼────────────────────────────┐
 │ Privileged response broker    │   │ Customer management/evidence      │
 │ Independent authorization     │   │ Enrollment + policy distribution  │
 │ Preconditions + scope + expiry│   │ Fleet correlation + incident UI    │
 │ Apply → verify → compensate   │   │ Read-only cloud audit connectors   │
 └──────────────┬────────────────┘   │ Separate approved cloud responder │
                │                    │ Updates + signed evidence receipts │
       OS-native enforcement         └─────────────────▲─────────────────┘
       / recovery workflow                             │ normalized evidence
                                       ┌───────────────┴──────────────────┐
                                       │ Optional SDN / EDR / IDS adapters│
                                       │ OS-Ken / OVS remain optional      │
                                       └──────────────────────────────────┘
```

The event path and the command path have different authorization. Supplying evidence never grants the right to execute a command. Neither arbitrary shell execution nor arbitrary cloud API invocation is part of the management protocol.

### 6.1 Native sensor and export helper

Collect bounded process execution/exit, privilege changes, relevant file events, socket activity and OS authentication events. Add boot/session/cgroup/container identity. Use an existing maintained sensor where it meets the contract; Tetragon provides relevant Linux process, syscall, file and network events [S06]. A sensor adapter is not permission to enable all available tracing policies.

Evaluate existing export APIs carefully. A read consumer must not receive access to an API that can also modify tracing policy. Put a read-only event exporter between that API and the Python core when necessary [S07].

Fallback collectors must advertise lower coverage. Polling a process table cannot claim to observe every short-lived process. Do not run several heavyweight agents by default; select one baseline sensor and optional explicitly justified integrations.

Native code is acceptable for OS-specific hooks and a small privileged helper. Python remains the main language for domain logic, detectors, correlation, policy, APIs and orchestration. Do not implement new cryptography or a new kernel driver merely to claim the entire product was written from scratch.

### 6.2 Python core

Run unprivileged with bounded IPC, queues and local persistence. Use a stable async/event model independent of Eventlet. Normalize observations into a versioned envelope. Maintain recent entity relationships and detector state. Evaluate local approved rules without needing a cloud round trip or hosted LLM.

Detectors are plugins with declarative subscriptions, required capabilities, state limits and processing budgets. They emit findings; they cannot write policy, manipulate system networking, execute shell commands or open arbitrary outbound connections. Isolate an experimental ML detector in a separate worker so model failures cannot take down deterministic protection.

### 6.3 Privileged response broker

Accept only schema-validated finite action types over authenticated local IPC. Re-check policy, authorization, scope, target identity, freshness, expiry, impact limits and platform capability. Use OS APIs or fixed executable/argument templates; never concatenate model-generated commands.

Keep its protocol intentionally small. A broad `run_command()` endpoint would convert the platform into remote administration software with a large attack surface.

### 6.4 Customer management service

Start as a modular service with durable metadata storage and customer-controlled evidence objects, not a large microservice mesh. Separate enrollment, policy publication, event ingestion, incident investigation, response authorization and update metadata by permissions even if some initially share a deployment.

Agents initiate outbound authenticated connections. Ingest binds tenant and agent identity to the authenticated credential rather than trusting a JSON `tenant_id`. Read-only collection roles and state-changing cloud response roles are distinct. Expensive or destructive fleet actions require approvals and impact budgets.

### 6.5 Cloud connectors

Collect scoped identity, audit, configuration and workload inventory events. Record service, region, account identity locally, event time, arrival time and collection completeness. Missing data-event logging is a coverage gap, not proof that storage access never occurred.

Do not classify all cloud evidence as subsecond real time. CloudTrail trail log delivery is normally measured in minutes and AWS does not guarantee its average delivery time [S17]. Fast local enforcement cannot depend on that log arriving first.

### 6.6 AI application gateway and SDK

Use explicit integration at retrieval, model invocation and tool execution boundaries. A network-only host sensor cannot infer prompt injection semantics from encrypted API traffic.

Place tool credentials and unrestricted network access outside the LLM process. Enforce original user/workload authorization at the actual tool/resource, not only on a prompt. A proxy that can be bypassed by direct tool credentials does not provide complete mediation [S03].

The SDK produces identity/provenance metadata. When the application itself is compromised, SDK telemetry is lower-trust evidence; retain independent host and cloud observations.

## 7. Common schemas and identity

### Event envelope

The following is an interface proposal, not implemented API documentation:

```json
{
  "schema_version": "1",
  "event_id": "globally-unique-id",
  "tenant_id": "bound-to-authenticated-enrollment",
  "agent_id": "enrolled-instance-id",
  "boot_id": "boot-instance-id",
  "sensor_id": "linux-process-exporter",
  "sensor_version": "pinned-version",
  "sequence": 412,
  "event_time_utc": "RFC3339 timestamp",
  "observed_monotonic_ns": 123456789,
  "received_time_utc": "RFC3339 timestamp",
  "kind": "process.exec",
  "subject": {
    "workload_id": "stable-workload-reference",
    "process": {"pid": 1842, "start_time_ns": 123000000},
    "container_id": null
  },
  "attributes": {},
  "provenance": {
    "source_event_ids": [],
    "collection_method": "kernel_sensor",
    "trust_boundary": "guest_kernel",
    "derived": false
  },
  "quality": {
    "complete": true,
    "loss_count_since_previous": 0,
    "clock_uncertainty_ms": 0,
    "capability_manifest_version": 1
  },
  "privacy_class": "security_metadata",
  "raw_evidence_ref": null
}
```

Never identify a process by PID alone or a cloud workload by IP/MAC alone. Include boot and process-generation information, container/cgroup context and authenticated workload enrollment. Handle replacement VMs, reused addresses, cloned images and re-enrollment explicitly.

Use SPIFFE-compatible workload identities or a comparable established PKI implementation; SPIFFE defines short-lived identity documents and mutual authentication across heterogeneous environments [S08]. The certificate identifies its holder, not the correctness of every statement the holder makes.

Use OCSF mappings for interoperability where appropriate [S18]. Preserve internal domain detail instead of forcing all events into lossy generic strings. External schema compatibility does not provide cryptographic integrity by itself.

### Finding

A finding includes its detector/version, affected entities, threat hypothesis, supporting evidence, contradictory evidence, telemetry gaps, severity, confidence basis, status and proposed response classes. Severity, confidence and sensor health are separate fields.

### Action proposal

```json
{
  "action_id": "idempotency-key",
  "tenant_id": "authenticated-tenant",
  "target": {"agent_id": "a1", "boot_id": "b1", "process_start_id": "p1"},
  "type": "restrict_workload_egress",
  "parameters": {"approved_destination_set": "policy-set-reference"},
  "policy_version": "signed-policy-version",
  "finding_ids": ["f1"],
  "issued_at": "RFC3339 timestamp",
  "expires_at": "RFC3339 timestamp",
  "preconditions": ["target-generation-matches", "management-path-preserved"],
  "approval_ref": "approval-or-preauthorized-policy-reference",
  "verification_plan": "egress-connectivity-v1",
  "compensation_plan": "restore-owned-rule-set-v1"
}
```

Reject replayed, cross-tenant, expired, generation-mismatched or unauthorized actions. Retries are idempotent. Distinguish requested, applied, effect-verified, compensation-pending, compensated and failed states.

## 8. Evidence correlation and decision discipline

Maintain an entity graph of processes, workloads, files, users, identities, connections, cloud sessions, model versions, retrieval documents and tool calls. Give edges explicit time windows and provenance. Do not infer identity merely from simultaneous timestamps or shared NAT addresses.

Use temporal rules first. A workload profile might flag an unexpected shell spawned by a web worker; an unrelated shell in an authorized build worker is a necessary benign control. Add network or credential evidence when available, but do not require multiple signals for a direct, fully mediated authorization violation.

**No double counting:** three detectors consuming the same process event are not three independent witnesses. Deduplicate raw events and group derived evidence by common source and trust boundary. Do not multiply independent failure probabilities unless independence has actually been justified.

**Unknown remains unknown:** when required telemetry is missing, return an explicit incomplete-evidence state. Do not use missing observations as evidence of safety. An inconclusive outcome must not automatically cause broad quarantine either; the policy defines bounded behavior under uncertainty.

Start with explainable deterministic policies. Add calibrated statistical models only after meaningful held-out data exist. No arbitrary score labeled `97% confidence`. ML drift or anomaly magnitude alone does not establish malicious intent.

## 9. Protection packs and limits

All entries below are proposed capabilities. Each needs its own dataset/scenario, required sensor set, false-positive controls and release evidence.

| Pack | Attack/abuse classes | Evidence needed | Bounded response and principal limitation |
|---|---|---|---|
| Host execution | Unexpected child processes, suspicious interpreter use, privilege transitions | Process lineage, current credentials, workload profile | Restrict a specific process/workload; not universal zero-day detection. |
| Persistence and file integrity | Unauthorized service/startup/config changes, executable replacement | Scoped file events, package/image manifests, change authorization | Alert/quarantine artifact/rebuild through approved workflow; hashes do not prove benignness. |
| Identity | Login abuse, unauthorized privileged sessions, credential misuse | OS auth, identity-provider and cloud audit | Rate-limit/revoke scoped access when supported; unusual geography/IP alone is not proof. |
| Network behavior | Reconnaissance, lateral movement, beacon-like patterns, exfiltration indicators | Process-associated flows, approved DNS/network sensors, destination policy | Restrict specific egress; encrypted content and legitimate administration are important ambiguities. |
| Availability | Event floods, process/resource exhaustion, application or AI cost abuse | Queue/drop metrics, cgroup resources, request/concurrency/cost counters | Per-workload limits and admission control; upstream volumetric DDoS requires upstream protection. |
| Container/workload integrity | Unexpected privileges, mount/namespace use, image drift | Runtime and orchestration context | Workload isolation/redeployment; not blanket container-escape prevention. |
| Cloud control plane | Unauthorized role/policy changes, unexpected exposure, suspicious API sequences | Cloud audit/configuration and ownership context | Approved scoped remediation; delivery delays and account privilege limits are explicit. |
| SDN topology/flow integrity | Location hijack, link fabrication, inconsistent flow state | OpenFlow/topology events and independent lab traffic | Existing optional SDN pack; ordinary VM agent does not control the provider's virtual switches. |
| AI request/output | Injection indicators, disclosure policy violations, unsafe output use | Application-integrated prompts/provenance and output sink context | Deny unsafe downstream action; no universal semantic injection detector. |
| AI tools and RAG | Excessive agency, cross-tenant retrieval, memory poisoning, SSRF | User authorization, source ACLs, tool arguments and actual execution | Resource-side deny, capability revocation, corpus quarantine; full coverage requires mediation. |
| Model and pipeline integrity | Unapproved weights/adapters, poisoned source changes, unsafe artifacts | Approved manifests, provenance, admission tests, evaluation sets | Reject/roll back unapproved artifacts; a signed malicious upstream model can still pass integrity checks. |
| Platform trust | Invalid or stale attestation, boot/firmware measurement mismatch | Supported platform attestation and independent verifier | Reduce privileges/isolate/rebuild; no generic guarantee against hypervisor or firmware compromise. |

Use third-party IDS/EDR findings as additional evidence through adapters, not as unverified truth. A vendor feed entry is neither a proof nor an authorization to block all matching systems.

### Clarifying ROT

Do not assume the owner's earlier term ROT has one established meaning. Model-editing trojan research such as Concept-ROT [S19] is distinct from Root-of-Trust attacks. Keep model-trojan and hardware-attestation requirements separate until terminology is confirmed. Routing integrity is another distinct domain.

For model trojans, require model/adapter/tokenizer/config manifests, admission evaluation, behavioral regression sets and protected update authority. Runtime hash checking can detect unapproved modification after enrollment; it cannot establish that the originally approved model was never poisoned.

## 10. AI-specific control flow

```text
Authenticated principal
  → application authorization and budgets
  → permission-aware retrieval
  → source provenance and untrusted-content marking
  → model invocation with bounded input/output
  → typed action proposal
  → independent tool/resource authorization
  → constrained executor with scoped credentials
  → validated result and permitted output sink
  → correlated host/cloud/application evidence
```

RAG must filter by the requesting principal's actual authorization before protected content enters the model. Cache keys must include tenant/principal permission scope and source version. Re-check access when returning cached material after permission changes. Keep retrieved instructions lower-trust than authenticated policy. Source authenticity and source factual correctness are different properties [S05].

Tool execution must apply action-specific and resource-specific permissions, verified destinations, parameter bounds, timeouts, concurrency and monetary limits. Enforce SSRF defenses at the fetcher/network boundary, including redirects and resolved destinations; prompt wording is not a substitute [S04]. Preserve required platform services through explicit workload-specific policy rather than global metadata blocking.

The book's action/capability/time/loop limits are adopted as requirements, not as a promise that any named guardrail library implements them completely (B1 pp.715–724). No model may extend its tools, modify its grants, replace security policy or approve its own high-impact action.

Keep memory namespaces distinct: authenticated owner policy, ordinary conversational memory, retrieved content and model proposals. A summary of untrusted content must not be promoted into authoritative policy. Preserve provenance across compaction and checkpoints.

An optional security copilot may summarize already-authorized evidence and propose investigations. It has no root shell, signing key, unrestricted cloud role, or direct enforcement API. Its input may itself contain attacker-controlled logs, so complete mediation applies to the copilot too.

Protecting AI systems does not require using an LLM in the security product. Local deterministic protection must function with every LLM disabled.

## 11. Response safety and recovery

Use a controlled state machine:

`OBSERVE → INVESTIGATE → PROPOSE → AUTHORIZE → APPLY → VERIFY → MAINTAIN/COMPENSATE → RECOVER`

Deny unsafe tool actions at their resource boundary even when the surrounding model appears confident. Use observe-only for newly deployed behavioral detectors. Automatic host containment requires a preapproved policy and tested target-specific preconditions.

Response options are finite: emit finding; increase bounded telemetry; reject a mediated request; throttle a workload; restrict a destination set; quarantine an approved test artifact; terminate a confirmed target when policy allows; ask the customer orchestrator to replace a compromised workload.

Not all actions are reversible. Removing an owned firewall rule can be compensated; killing a process cannot recover unsaved work. Revoking a leaked credential does not erase copies already stolen. Restoring connectivity is not proof of eradication. Mark destructive effects separately and require the corresponding authority.

Every network action owns a narrow rule namespace and preserves unrelated firewall/CNI/EDR rules. No global flush. Protect the actual management path, DNS/identity dependencies needed for recovery and an out-of-band route where available. Test connection tracking and established sessions; a reported rule installation is not a demonstrated traffic cutoff.

Use a local action expiry/watchdog independent of a cloud round trip. Specify per-action behavior when central management disappears: maintain a last-known-good preventive rule, expire a temporary containment, or disable new high-impact automation. Do not pick one universal fail-open/fail-closed rule.

After serious compromise, favor replacing the workload from a verified image and rotating affected credentials over claiming that automatic file deletion cleaned the host. Preserve authorized forensic evidence, validate restored operation, and monitor after re-entry (B1 pp.950–951).

## 12. Fleet enrollment, updates and self-protection

Enrollment uses a one-time, short-lived, tenant-bound bootstrap grant. Generate a per-installation key; do not bake reusable identities into VM images. Validate cloud/workload claims and approve identity issuance. Rotate credentials and revoke enrollment explicitly. Re-enrollment after cloning/rebuild must not silently inherit the old host's trust.

Separate permissions for reading findings, authoring policies, approving containment, signing releases and exercising emergency recovery. A central administrator's ordinary session should not be an unrestricted root-command channel to the entire fleet.

Sign agent, detector, configuration, model and update manifests. Pin trust roots, verify artifact hashes and metadata expiry/version constraints, test rollback/replay resistance, and use staged rollouts. TUF is an appropriate established update-security framework to evaluate [S11]. Signatures do not replace review and testing.

Privileged service configuration, executable paths and allowed action policy must not be writable by the unprivileged analysis process. Deny runtime plugin installation from arbitrary URLs. Keep raw sensor event access read-only. Scan and test update packages before canary promotion. Retain a separately authorized emergency recovery path.

Cloud operations use customer-approved least privilege. Long-term bootstrap credentials that can assume a role are still valuable to an attacker; do not call them harmless. Root-key retirement remains an owner action [S20]. Account closure is not required merely to deactivate a compromised root access key.

## 13. Privacy, evidence and storage

Three different stores must remain separate:

1. Developer project memory: existing bounded JSONL, 91-effective-day policy and durable decisions.
2. Runtime security state: current entities, detector windows, pending actions and local delivery spool.
3. Incident evidence: protected investigation artifacts with their own time-based retention, holds and access audit.

Do not apply the developer memory's 8 MiB cap or inactivity clock to production incident retention.

Minimize collection at the sensor. Default to metadata, scoped hashes and rule/evidence identifiers, not complete file contents, raw command arguments, packet payloads, prompts or tokens. Sensitive optional captures require a case-specific policy, bounded size and separate authorized storage. Redaction is a safeguard, not guaranteed DLP.

Runtime data stays on the host or in the customer's approved management/evidence environment. No default vendor telemetry, hosted-model inference, remote embedding or cross-customer model training. Development-time permission to share bounded excerpts with Claude/Codex is not customer production-data permission.

A production spool must be byte-bounded, crash-recoverable and explicit about dropped data. A transactional local database is a reasonable candidate for runtime state; this does not reopen the already selected JSONL developer-memory design. Account for database journals, temporary files and checkpointing in its resource budget.

Illustrative storage arithmetic, not a measured workload: 100 events/s × 500 bytes/event × 86,400 s/day = 4.32 GB/day before indexes, protocol overhead or replicas. A small disk cannot retain unlimited raw telemetry. Aggregate low-value repeat events, reserve space for incidents/health, and export approved evidence with acknowledgments. Dropping data must change the coverage/health status.

Protect evidence using sequence numbers, authenticated transport, cryptographic integrity records and off-host receipts or immutable storage where configured. Integrity protects already-received evidence; it does not make a compromised source truthful. Record gaps and late arrivals. Hash chains kept only on a root-compromised host are insufficient.

## 14. Reliability and failure behavior

Bound events, queue depth, per-entity state, parser lengths, decompression, regex execution, model inference, file scanning, retries, parallel tasks and action lifetimes. Rate-limit per workload and reserve capacity for essential telemetry. A compromised workload must not monopolize the agent.

Use explicit lifecycle phases: startup validation, capability discovery, sensor readiness, policy readiness, observation, shutdown drain and completion. Readiness includes live sensor export and a writable durable spool, not merely an open port. Expose sensor loss, missed sequence ranges, stale cloud data and disabled rules.

Reconcile pending actions after restart using recorded target generation and actual OS state. Never repeat a non-idempotent operation because the acknowledgment was lost. Time-based detection uses a monotonic clock within a boot and explicit uncertainty across machines; cloud event time and local arrival time are different.

Supervise the SDN process separately. Require bounded graceful shutdown; escalate externally and record abnormal termination. Verify that the old process exited and the listener port is released before the next test. Empty event output cannot pass a negative-control test without independent evidence that the sensor was healthy throughout.

## 15. Scientific evaluation plan

Create a versioned Test and Evaluation Master Plan before broad release, following B1 pp.843–846. Define the hypothesis, scope, baseline, sensors, benign controls, workload, environment, acceptance thresholds, sample size and failure interpretation for each experiment.

### Falsifiable hypotheses

H1: Adding process identity to network evidence reduces false containment versus network-only detection at a matched detection requirement.

H2: Independent tool/resource authorization prevents the defined unauthorized side effects even when an LLM follows injected instructions.

H3: Detecting sensor loss prevents false clean-health declarations when evidence is missing.

H4: Local approved protection continues within its stated scope during management outages, without indefinite unintended containment.

H5: The selected sensor/core configuration stays within approved overhead and event-loss limits under the declared workload.

H6: Signed update metadata, target generation and action idempotency prevent the tested rollback, replay and cross-workload mistakes.

These are hypotheses to test, not promises.

### Experiment rules

Ground truth is written only by the scenario harness. Sensor events, findings and action receipts are written only by the system under test. Join them after collection. Include detector-disabled, sensor-disabled and enforcement-disabled controls, alongside realistic benign tasks.

For AI mediation, test both scripted adversarial action proposals and an actual approved model integration. A deterministic fake proves the broker boundary but not the model's prompt-injection resistance. Keep those claims separate.

Split ML data by independent runs, workloads, time ranges and environment—not randomly shuffled near-duplicate events from one run. Fit transformations on training folds only. Keep labels inaccessible to online features. Hold out attack families where meaningful, record selection limits, and test model poisoning/evasion against the security model itself. No automatic learning from unreviewed production feedback.

### Metrics

Measure detection recall and precision per scenario; false findings per host-day; false automatic containment per workload-day; prevented versus merely detected actions; event loss; evidence delay; p50/p95/p99 response stages; protected-app overhead; CPU/RSS/disk/bandwidth; recovery time; rollback success; outage tolerance; and cost per validated test run.

Define total response latency as:

`capture delay + processing/queue delay + decision delay + enforcement delay + effect-verification delay`.

A fast Python function does not establish fast prevention. Log-derived detection is different from synchronous pre-action denial.

For zero observed failures in n independent Bernoulli trials, the exact one-sided 95% upper bound is `1 - 0.05^(1/n)`, approximately `3/n`. At n=100 this is about 2.95%, not zero. Repeated dependent events do not count as independent trials.

Coverage is a matrix of threat × platform × sensor set × control × scenario × evidence status. A count of mapped ATT&CK/ATLAS techniques must never be described as a percentage of all attacks prevented.

### Initial engineering budgets

Before implementation benchmarks, propose and approve per-profile budgets instead of advertising performance. A reasonable measurement plan starts with small/medium/load profiles and records total agent-plus-sensor overhead. Set separate limits for normal operations, incident capture and deliberate stress tests. Fixed resource ceilings must produce explicit degradation rather than invisible blindness.

## 16. Minimum adversarial acceptance catalog

| ID | Controlled test | Required outcome |
|---|---|---|
| CT-01 | Ordinary server with no SDN dependencies | Agent starts and reports truthful host capabilities. |
| CT-02 | Harmless unexpected child process from a test service | Attributed finding; corresponding authorized job is a benign control. |
| CT-03 | Test-only protected-file modification | Correct file/workload evidence without leaking contents. |
| CT-04 | Simulated credential misuse | Correlated identity evidence; no heuristic-only account-wide revocation. |
| CT-05 | Test namespace egress violation | Approved narrow action has independently verified traffic effect. |
| CT-06 | Agent/core dies during temporary containment | Defined expiry/recovery works and is audited. |
| CT-07 | Sensor export disappears | Coverage becomes degraded, never clean/no-attack. |
| CT-08 | Burst exceeds queue/state limits | Bounded memory; event loss visible; critical health remains available. |
| CT-09 | Duplicate/out-of-order/replayed event | Correct deduplication and no repeated destructive response. |
| CT-10 | PID reused or workload replaced before action | Broker refuses stale target. |
| CT-11 | Cross-tenant identity in event/action payload | Authenticated tenant boundary rejects it. |
| CT-12 | Malicious instruction in synthetic retrieved document | Unapproved tool side effect denied independently of model behavior. |
| CT-13 | Unauthorized RAG retrieval/cache reuse | Protected content does not reach the model or unauthorized response. |
| CT-14 | AI tool attempts disallowed metadata/private destination | Fetcher/network policy denies it; authorized platform traffic still works. |
| CT-15 | Tool loop or request-cost amplification | Enforced per-task and aggregate limits terminate the run. |
| CT-16 | Tampered model/adapter/update metadata | Admission fails with actionable provenance finding. |
| CT-17 | Validly signed but behaviorally malicious test model | Integrity and behavioral evaluation outcomes are distinguished. |
| CT-18 | Stale/invalid attestation where supported | Trust downgrade without claiming all compromise is detected. |
| CT-19 | Management outage and reconnect | Local approved behavior, bounded spool and idempotent reconciliation. |
| CT-20 | Failed update/canary | Fleet rollout stops; tested authorized rollback/recovery available. |
| CT-21 | Legacy SDN benign move/hijack and negative control | Existing independent real-OVS evidence remains reproducible. |
| CT-22 | Forced SDN-controller shutdown / stale listener | Incomplete run cannot masquerade as successful negative control. |

All attack-like behavior is confined to owned, authorized test assets, synthetic records and harmless markers. No production credential dumping, arbitrary public scanning or uncontrolled flooding is required.

## 17. Incremental repository integration

Preserve:

```text
development/src/sdnguard/
development/tests/
development/infra/
tools/
tests/tools/
tests/memory/
docs/
memory/
```

Do not rename the entire repository or force every domain type into a generic base class. Introduce the smallest shared contracts needed by a second adapter. A possible additive structure is:

```text
development/src/
  sdnguard/                   # existing SDN implementation retained
  padmavyuh/                  # proposed shared/host platform package
    contracts/                # events, identities, capabilities, actions
    agent/                    # lifecycle, local state, health
    collectors/               # adapters to approved sensor exports
    detectors/                # host, identity, behavioral packs
    correlation/              # provenance-aware temporal relations
    policy/                   # pure decision logic, signed-policy loader
    response/                 # unprivileged client; no root shell
    fleet/                    # enrollment, mTLS delivery, policy cache
    ai/                       # optional SDK/gateway contracts
    cloud/                    # management-side connector contracts
    evidence/                 # manifests, receipts, integrity checks
native/                       # only justified OS helper implementation
```

The name is provisional. Existing compatible code should be reused or extracted under tests, not copied into a second divergent core. `tools/` are development governance, never production privileged executables by default.

## 18. Branch and milestone plan

Retain completed P0–P6 task IDs and their evidence. Do not retroactively label new host/AI capabilities as completed because similarly named SDN tasks passed. Complete the bounded current SDN experiment while creating a second plain-server vertical slice.

| Task | Branch | Dependency / merge gate |
|---|---|---|
| V2-ARCH-01 | `docs/v2-architecture-01-cloud-agent-contract` | Approve scope, threat model, capability matrix and evidence definitions. |
| V2-CORE-01 | `feat/v2-core-01-events-capabilities` | Versioned common contracts; SDN regression tests remain green. |
| V2-HOST-01 | `feat/v2-host-01-linux-sensor-adapter` | Real Linux events, explicit sensor-loss test, no OVS installed. |
| V2-HOST-02 | `feat/v2-host-02-local-detection` | One attributed harmless violation + benign control + detector-disabled test. |
| V2-SAFE-01 | `feat/v2-response-01-privileged-broker` | Independent authorization, generation checks, no arbitrary shell endpoint. |
| V2-SAFE-02 | `test/v2-response-02-containment-recovery` | Real scoped effect, restart/outage/expiry/recovery evidence. |
| V2-FLEET-01 | `feat/v2-fleet-01-enrollment-delivery` | Identity issuance/rotation, cross-tenant denial, offline spool recovery. |
| V2-FLEET-02 | `feat/v2-fleet-02-policy-update-trust` | Signed policy/update metadata, canary, replay/rollback defenses. |
| V2-CLOUD-01 | `feat/v2-cloud-01-readonly-audit` | Scoped connector with positive control, lag/coverage metadata. |
| V2-AI-01 | `feat/v2-ai-01-tool-mediation` | Synthetic unsafe tool proposals denied at resource boundary. |
| V2-AI-02 | `feat/v2-ai-02-rag-scope-provenance` | Cross-tenant retrieval and stale-cache denial. |
| V2-AI-03 | `feat/v2-ai-03-model-admission` | Manifest integrity + separate behavioral admission evaluation. |
| V2-TEST-01 | `test/v2-assurance-01-cross-layer-scenarios` | CT catalog, independent truth, matched benign controls. |
| V2-PERF-01 | `test/v2-performance-01-profile-benchmarks` | Whole-agent overhead, event loss, latency and offline behavior measured. |
| V2-PORT-01 | `spike/v2-platform-01-additional-profiles` | Windows/container/serverless capability ADRs; no untested parity claim. |
| V2-RELEASE-01 | `release/v2-candidate-01-assurance` | Supported-profile release evidence and independent security review status. |

Existing P7 response, P8 reliability, P9 ML, P10 performance, P11 deployment, P12 packaging and P13 assurance remain useful disciplines. Rebaseline their acceptance criteria against v2. P13-SDN and P13-cloud-agent are different assurance scopes.

Do not let optional Windows, serverless, attestation or ML tracks delay a useful validated Linux host-agent release. Keep them explicit, funded, testable expansion tracks rather than silently dropped promises.

## 19. Release gates and operational boundaries

A release candidate requires evidence for installation, enrollment, sensor health, ordinary-host detection, scoped response, recovery, management outage, bounded resources, policy/update trust, applicable AI/cloud integrations and customer-data boundaries.

Security-critical review must not be reduced to two models agreeing. Record qualified independent review as complete only when it occurred. No claimed patent novelty, patentability or freedom to operate follows from this architecture; private patent mapping remains local and separately reviewed.

Deploy progressively: lab → staging observe-only → canary monitored response → supported production profile after explicit acceptance. Every enabled feature has documented prerequisites and residual risks.

No unlimited AWS authorization is implied by this design. Every run has an owner-approved budget, TTL, resource manifest and cleanup procedure. Delete only resources proven owned by that run/stack; an account-wide resource count greater than an old baseline is not ownership evidence. Preserve evidence before teardown and include storage, endpoints, public-address and network charges when applicable.

The completion condition is not a task number. It is a supportable claim about specified workloads, attacks, controls and recovery under stated assumptions.

## 20. Immediate next implementation outcome

After the small architecture-contract branch, produce this evidence on an ordinary Linux VM:

```text
No OVS / no Mininet / no OpenFlow / no hosted LLM required
  → protected test service emits a harmless policy-violating action
  → real OS sensor records it with process/workload identity
  → Python detector emits independently generated evidence
  → broker verifies a preauthorized, narrowly scoped response
  → independent harness verifies the effect and benign-service continuity
  → expiry/recovery succeeds even across an agent restart
  → evidence and capability status remain honest
```

This is the decisive transition from an SDN research prototype into a cloud-server security product.

## Source ledger

B1. EC-Council, *Certified Offensive AI Security Professional Version 1*, user-supplied `COASP-book.pdf`; relevant physical PDF pages and interpretations listed in section 2. No redistribution of the source book is included.

The following primary sources were accessed on 2026-09-20. References identify design inputs, not certification of this implementation.

S01. NIST SP 800-207, *Zero Trust Architecture*. https://csrc.nist.gov/pubs/sp/800/207/final

S02. NIST AI 100-2 E2025, *Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations*. https://csrc.nist.gov/pubs/ai/100/2/e2025/final

S03. OWASP, *LLM06:2025 Excessive Agency*. https://genai.owasp.org/llmrisk/llm062025-excessive-agency/

S04. OWASP, *Server Side Request Forgery Prevention Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

S05. OWASP, *LLM08:2025 Vector and Embedding Weaknesses*. https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/

S06. Tetragon, *Overview*. https://tetragon.io/docs/overview/

S07. Tetragon, *Threat Model*. https://tetragon.io/docs/threat-model/

S08. SPIFFE, *SPIFFE Overview*. https://spiffe.io/docs/latest/spiffe-about/overview/

S09. Kubernetes, *Secrets*. https://kubernetes.io/docs/concepts/configuration/secret/

S10. IETF RFC 9334, *Remote ATtestation procedureS (RATS) Architecture*. https://www.rfc-editor.org/rfc/rfc9334.html

S11. The Update Framework, *Specification*. https://theupdateframework.github.io/specification/latest/

S12. Python, *os._exit*. https://docs.python.org/3/library/os.html#os._exit

S13. Eventlet, maintenance warning. https://eventlet.readthedocs.io/en/latest/

S14. Microsoft, *Windows Filtering Platform*. https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page

S15. Apple, *Endpoint Security*. https://developer.apple.com/documentation/endpointsecurity

S16. AWS, *Understanding the Lambda execution environment lifecycle*. https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html

S17. AWS, *How CloudTrail works*. https://docs.aws.amazon.com/awscloudtrail/latest/userguide/how-cloudtrail-works.html

S18. Open Cybersecurity Schema Framework. https://ocsf.io/

S19. Grimes et al., *Concept-ROT: Poisoning Concepts in Large Language Models with Model Editing*, ICLR 2025. https://arxiv.org/abs/2412.13341

S20. AWS, *Root user best practices*. https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html

S21. OWASP, *LLM01:2025 Prompt Injection*. https://genai.owasp.org/llmrisk/llm01-prompt-injection/

S22. MITRE ATT&CK. https://attack.mitre.org/

### Claim record template

```yaml
claim_id: CLAIM-REPLACE-ME
claim: Precisely scoped statement
status: PROPOSED
supported_platforms: []
required_sensors: []
required_enforcement_points: []
attacker_capabilities: []
assumptions: []
source_references: []
implementation_commit: null
tests: []
evidence_runs: []
negative_controls: []
benign_controls: []
measured_results: {}
known_limitations: []
review_status: NOT_PERFORMED
```
