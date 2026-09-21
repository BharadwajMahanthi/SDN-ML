# Platform matrix

A capability is `SUPPORTED` only where it has actually been validated. Parity
between kernels is never inferred — two runs on one Docker VM are one
platform validation, not two.

| Capability | macOS native | macOS + Docker Desktop VM | Ubuntu AWS x86_64 | Ubuntu arm64 |
|---|---|---|---|---|
| Full Python test suite | SUPPORTED | SUPPORTED | SUPPORTED | NOT_RUN |
| Peer-credential authentication | SUPPORTED (`LOCAL_PEERCRED`) | SUPPORTED (`SO_PEERCRED`) | SUPPORTED | NOT_RUN |
| Broker over a real Unix socket | SUPPORTED | SUPPORTED | SUPPORTED | NOT_RUN |
| nftables IPv4 egress restriction | NOT APPLICABLE | **VALIDATED** | **NOT_RUN** | NOT_RUN |
| nftables IPv6 restriction | NOT APPLICABLE | NOT IMPLEMENTED (KF-38) | NOT IMPLEMENTED | NOT IMPLEMENTED |
| netlink proc connector | NOT APPLICABLE | **UNAVAILABLE** (`CONFIG_CONNECTOR` unset) | SUPPORTED | NOT_RUN |
| Full DETECT→CONTAIN chain | NOT APPLICABLE | NOT POSSIBLE (no proc connector) | **NOT_RUN** | NOT_RUN |

Kernel measured for the Docker Desktop row: `6.12.76-linuxkit`, aarch64.

## Why the AWS column matters

Docker Desktop's VM is the *development and integration* environment. It is a
real kernel and its evidence is real, but every containment run so far has
executed against that one kernel, in a container, on one architecture. Three
things are therefore untested:

- **A different kernel build.** `meta skuid` semantics, nftables JSON
  handling and hook ordering are all kernel-version-dependent.
- **A host rather than a container.** A container's network namespace is not
  a host's, and this repository does not claim they have identical isolation
  semantics.
- **x86_64.** Every physical result so far is aarch64.

## Running the independent reference validation

Requires AWS access, which is currently an owner-level blocker (see
`docs/CURRENT_STATE.md`: `REMOTE_PUSH_BLOCKED` is separate, but the root-key
action and lab credentials are outstanding).

```bash
development/infra/lab/create.sh                      # CloudFormation lab
development/infra/lab/deploy.sh                      # ship the package via SSM
development/infra/lab/remote.sh -- \
  python3 /opt/annulon/development/infra/local/containment_experiment.py \
    --destination <lab-peer-ip> --ttl 30
development/infra/lab/fetch_evidence.sh docs/evidence/v2-safe-03-ubuntu.json
development/infra/lab/destroy.sh
```

The experiment is platform-agnostic on purpose — it takes a destination and a
TTL and nothing else — so the Ubuntu run is the same code, not a port of it.

## A local alternative to AWS

A Lima VM gives a stock Ubuntu kernel on the Mac, which covers the different
kernel build and the proc connector, but not x86_64 and not a non-container
host in a different network environment:

```bash
brew install lima
limactl start --name=annulon template://ubuntu-lts
limactl shell annulon
```

This is a weaker form of independence than AWS and is recorded as such.
