# syntax=docker/dockerfile:1
FROM python:3.12-slim

# ---------- system ----------
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ---------- non-root user ----------
RUN useradd --create-home --shell /bin/bash fairewall
WORKDIR /app
USER fairewall

# ---------- Python deps ----------
# Copy only the package metadata first so the layer is cached
COPY --chown=fairewall:fairewall pyproject.toml ./
COPY --chown=fairewall:fairewall src/ ./src/

# Install the SDK + all platform adapters + the proxy/server extras
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir ".[sdk,proxy]"

# ---------- runtime ----------
ENV FAIREWALL_HOST=0.0.0.0
ENV FAIREWALL_PORT=8000
ENV FAIREWALL_AUDIT_PATH=/app/data/audit.jsonl

# Persistent audit log directory (mount as a volume)
RUN mkdir -p /app/data

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "-m", "uvicorn", "fairewall.server:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
