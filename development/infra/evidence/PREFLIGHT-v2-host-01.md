# AWS preflight — V2-HOST-01 Linux sensor evaluation

| Item | Value |
|---|---|
| Region | ap-south-1 |
| Instance | t3a.large (2 vCPU, 8 GiB, x86_64) |
| AMI | ami-0c0fd09cfe77b59dc — Ubuntu 24.04 LTS, pinned |
| Storage | 20 GiB gp3, encrypted |
| Hourly cost | $0.0518 (instance $0.0493 + storage $0.0025) |
| Expected runtime | 2–4 h |
| Expected spend | ~$0.21 |
| Resources | one CloudFormation stack: IAM role, instance profile, security group (no ingress), instance, volume |
| Network exposure | none inbound; egress 443/80 only; access via SSM Run Command |
| Credential | scoped `sdnguard` profile, temporary STS session |
| Cleanup | `destroy.sh`, then verification against the pre-create baseline |

Unchanged from the established small-lab pattern, so no new cost approval is
implied. **No OVS or OpenFlow is used in this task** — the point is an
ordinary Linux host.
