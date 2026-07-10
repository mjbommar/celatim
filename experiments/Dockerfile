# Lab host for the kick-the-tires experiments: a privileged container inside which
# we build a netns + veth topology (testbed.md Tier 1). Real kernel stack, real wire.
FROM python:3.14-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 ethtool tcpdump libpcap0.8 iputils-ping procps \
        iptables nftables \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir cryptography scapy

# celatim is pure stdlib; import it straight from the mounted source tree.
ENV PYTHONPATH=/work/src
ENV PYTHONUNBUFFERED=1
WORKDIR /work
