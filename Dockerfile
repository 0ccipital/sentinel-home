FROM python:3.13-slim

# Optional apt-cacher-ng proxy (pass --build-arg APT_PROXY=http://host:3142)
ARG APT_PROXY
RUN if [ -n "$APT_PROXY" ]; then \
      echo "Acquire::http::Proxy \"$APT_PROXY\";" > /etc/apt/apt.conf.d/00proxy; \
    fi

# System packages:
#   nmap        — required by python-nmap (NmapCollector)
#   libpcap0.8  — required by Scapy at runtime (SniffCollector)
#   libpcap-dev — required to build Scapy C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libpcap0.8 \
    libpcap-dev \
    iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/apt/apt.conf.d/00proxy

# uv for fast dependency resolution
RUN pip install --no-cache-dir uv

WORKDIR /app

# Copy dependency manifest first for Docker layer caching
COPY pyproject.toml ./
COPY uv.lock* ./

# Install dependencies only (project source not present yet)
RUN uv sync --no-dev --no-install-project

# Copy application source
COPY sentinel_home/ ./sentinel_home/

# Install the project itself now that source is available
RUN uv sync --no-dev

# /data is mounted from the Unraid "sentinel" share (read-write)
#   - /data/config.yaml   app config
#   - /data/sentinel.db   SQLite database
#   - /data/logs/         rotating log files
RUN mkdir -p /data/logs

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV CONFIG_PATH=/data/config.yaml

EXPOSE 8890
EXPOSE 514/udp

# Capabilities required at runtime (set in Unraid container config):
#   NET_RAW   — Scapy raw socket capture on eth0
#   NET_ADMIN — Scapy interface manipulation

# Run Alembic migrations then start the app
COPY alembic.ini ./
COPY alembic/ ./alembic/
CMD ["sh", "-c", "uv run alembic upgrade head 2>/dev/null; uv run sentinel-home"]
