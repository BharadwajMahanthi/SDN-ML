# A real Linux kernel's userland for Annulon's kernel-coupled work.
#
# This is not an emulation of Linux. On macOS, Docker Desktop runs a genuine
# Linux VM, and a container in it executes against that kernel: real nftables
# tables, real hooks, real packet counters. The same image runs unchanged on
# a Linux host and in the EC2 lab.
FROM debian:12-slim

RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
        nftables iproute2 iputils-ping python3 python3-pytest ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONPATH=/annulon/src
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /annulon
CMD ["/bin/bash"]
