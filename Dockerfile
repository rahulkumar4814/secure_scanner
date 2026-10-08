# SecureScan AI - hardened container image
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    TRIVY_CACHE_DIR=/app/data/trivy-cache SEMGREP_SEND_METRICS=off

RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/install_tools.sh /tmp/install_tools.sh
RUN bash /tmp/install_tools.sh && rm /tmp/install_tools.sh

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY securescan ./securescan
COPY policies ./policies
COPY rules ./rules
COPY samples ./samples

# Non-root user; only /app/data is writable
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin securescan \
    && mkdir -p /app/data && chown -R securescan:securescan /app/data
USER securescan

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1
CMD ["python", "-m", "securescan.cli", "serve", "--host", "0.0.0.0", "--port", "8000"]
