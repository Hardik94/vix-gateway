# MeshDrive from GitHub .deb (no source tree in the image).
# Default release: https://github.com/Hardik94/vix-gateway/releases/tag/v2.3.1
#
# Build (from this directory):
#   docker build -t meshdrive:2.3.1 .
# Or via compose from meshdrive-2.0/docker:
#   docker compose up --build

FROM ubuntu:24.04

ARG MESHDRIVE_VERSION=v2.3.1
# Deb filename uses version without leading "v"
ARG MESHDRIVE_DEB_VERSION=2.3.1
# Optional full override; if empty, built from VERSION + DEB_VERSION above
ARG DEB_URL=

ENV DEBIAN_FRONTEND=noninteractive \
    MESHDRIVE_ROOT=/opt/meshdrive \
    MESHDRIVE_CONTROL_HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        fuse3 \
        python3 \
        python3-venv \
        python3-pip \
        tar \
        adduser \
        openssl \
    && rm -rf /var/lib/apt/lists/*

# Download published .deb only — no MeshDrive source copied into the image.
ARG MESHDRIVE_VERSION
ARG MESHDRIVE_DEB_VERSION
ARG DEB_URL
RUN set -eux; \
    url="${DEB_URL}"; \
    if [ -z "${url}" ]; then \
      url="https://github.com/Hardik94/vix-gateway/releases/download/${MESHDRIVE_VERSION}/meshdrive_${MESHDRIVE_DEB_VERSION}_amd64.deb"; \
    fi; \
    echo "Downloading ${url}"; \
    curl -fsSL -o /tmp/meshdrive.deb "${url}"; \
    dpkg -i /tmp/meshdrive.deb || true; \
    apt-get update; \
    apt-get install -f -y; \
    rm -f /tmp/meshdrive.deb; \
    rm -rf /var/lib/apt/lists/*; \
    (test -x /opt/meshdrive/bin/meshdrive-agent || test -x /usr/local/bin/meshdrive-agent)

COPY entrypoint.sh /usr/local/bin/meshdrive-docker-entrypoint.sh
RUN chmod +x /usr/local/bin/meshdrive-docker-entrypoint.sh

WORKDIR /opt/meshdrive

# Agent API / Filebrowser / MCP SSE (when installed)
EXPOSE 12700 8080 9000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:12700/health" || exit 1

VOLUME ["/opt/meshdrive/var", "/opt/meshdrive/mnt"]

ENTRYPOINT ["/usr/local/bin/meshdrive-docker-entrypoint.sh"]
