# Sensor evaluation image. Carries every candidate so they can be measured
# against one another on one kernel, in one run, against one ground truth.
FROM debian:12-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
        bpftrace bpfcc-tools python3 python3-bpfcc iproute2 procps \
        ca-certificates nftables \
    && rm -rf /var/lib/apt/lists/*
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /annulon
