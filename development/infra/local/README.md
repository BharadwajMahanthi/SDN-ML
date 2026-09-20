# The Linux lab, on whatever machine you are sitting at

Annulon's kernel-coupled work — process events, packet-filter containment,
peer-credential authentication — has to be proven against a real kernel. This
directory makes that possible on a Mac without an AWS account.

It is not an emulation. On macOS, Docker Desktop runs a genuine Linux VM, and
a container in it executes against that kernel: real `nftables` tables, real
hooks, real packet counters. The image and the commands are identical on a
Linux host and in the EC2 lab.

```bash
./lab.sh build          # build the image
./lab.sh caps           # what this kernel can actually verify
./lab.sh test           # the response suite, against a real kernel
./lab.sh shell          # interactive root shell, repo mounted read-only
./lab.sh run <cmd...>   # one command in the lab
```

## Run `caps` first

`capabilities.py` measures rather than assumes: it opens a netlink socket
and runs `nft`, and reports what actually worked. Nothing is credited to a
mechanism that is not present, and an unavailable mechanism makes an
experiment `NOT_RUN` rather than approximated by something weaker.

## What each platform can verify, measured 2026-09-21

| Capability | macOS native | macOS + Docker | Ubuntu (EC2 / Lima) |
|---|---|---|---|
| Full Python test suite | yes | yes | yes |
| Peer-credential authentication | yes, `LOCAL_PEERCRED` | yes, `SO_PEERCRED` | yes, `SO_PEERCRED` |
| Broker over a real Unix socket | yes | yes | yes |
| `nftables` containment | no | **yes** | yes |
| netlink proc connector | no | **no** | yes |
| OVS datapath | no | yes | yes |

Measured on Docker Desktop's kernel 6.12.76-linuxkit (aarch64):
`CONFIG_NF_TABLES=y` but `# CONFIG_CONNECTOR is not set`. The proc connector
is therefore genuinely unavailable there, and the sensor says so loudly —
`SensorUnavailable: cannot open netlink socket: [Errno 93] Protocol not
supported` — rather than degrading to `/proc` polling, which was measured to
miss 500 of 500 short-lived processes while reporting no loss.

## Full parity, including the proc connector

A stock Ubuntu kernel ships `CONFIG_CONNECTOR=y` and `CONFIG_PROC_EVENTS=y`.
On macOS that means a Lima VM rather than Docker Desktop:

```bash
brew install lima
limactl start --name=annulon template://ubuntu-lts
limactl shell annulon
```

Then run the experiments in `development/infra/lab/` exactly as on EC2.
This is the only part of the system that a Mac cannot verify through Docker,
and it is called out here so nobody concludes the sensor works on evidence
that never covered it.
