# syntax=docker/dockerfile:1
# One image, several roles (FAIREWALL_ROLE):
#   sdk-gateway (default)  the platform-adapter gateway (fairewall.server), as before
#   lab                    the judge-facing Lab (python -m fairewall.lab)
#   gateway                a policy gateway with shared state (fairewall serve --database)
#   control                the control plane
#   anchor                 one anchoring pass (Cloud Run job, triggered by Cloud Scheduler)
#   migrate                create schemas and seed synthetic evidence, then exit
# Every role listens on $PORT (Cloud Run sets it).
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash fairewall
WORKDIR /app
RUN mkdir -p /app/data && chown -R fairewall:fairewall /app
USER fairewall
ENV PATH="/home/fairewall/.local/bin:${PATH}" PYTHONUNBUFFERED=1

COPY --chown=fairewall:fairewall pyproject.toml README.md ./
COPY --chown=fairewall:fairewall src/ ./src/
RUN pip install --no-cache-dir --user --upgrade pip \
 && pip install --no-cache-dir --user ".[sdk,proxy,lab]"

COPY --chown=fairewall:fairewall deploy/gcp/entrypoint.sh /app/entrypoint.sh

ENV FAIREWALL_ROLE=sdk-gateway \
    FAIREWALL_HOST=0.0.0.0 \
    PORT=8000 \
    FAIREWALL_AUDIT_PATH=/app/data/audit.jsonl

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fs "http://localhost:${PORT}/healthz" || curl -fs "http://localhost:${PORT}/health" || exit 1

ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
