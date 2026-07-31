# IronGate end-to-end test image.
#
# Mirrors what irongate-install.sh provisions on a real host, so the extracted
# source tree is exercised at the paths it actually runs from. This image is for
# testing only - it is not a deployment artifact.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Same system dependencies the installer apt-installs, plus tooling the checks need.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-dev \
        dnsmasq nftables nginx php-fpm php-sqlite3 sqlite3 jq \
        iproute2 iputils-ping net-tools procps curl ca-certificates \
        isc-dhcp-client \
        build-essential libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Python environment, at the same path the installer uses.
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/irongate/venv \
    && /opt/irongate/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/irongate/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

# Source laid out at the real runtime paths.
COPY src/   /opt/irongate/
COPY web/   /var/www/irongate/
COPY tests/ /opt/irongate/tests/
COPY config/ /opt/irongate/config/

# Stage scripts live in files rather than inline compose commands, because compose
# performs $VARIABLE interpolation on command blocks and mangles shell syntax.
COPY docker/stage-a.sh docker/stage-a-client.sh /opt/irongate/

RUN chmod +x /opt/irongate/irongate-blockchain \
             /opt/irongate/dhcp-notify.sh \
             /opt/irongate/irongate-updater.sh \
             /opt/irongate/stage-a.sh \
             /opt/irongate/stage-a-client.sh \
             /opt/irongate/tests/e2e-checks.sh 2>/dev/null || true

# dnsmasq must not auto-start; the harness starts it only after isolation is proven.
RUN mkdir -p /etc/irongate /var/lib/misc /var/log/irongate \
    && printf '' > /var/lib/misc/dnsmasq.leases

WORKDIR /opt/irongate
CMD ["/bin/bash"]
