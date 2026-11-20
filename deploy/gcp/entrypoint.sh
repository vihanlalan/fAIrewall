#!/bin/sh
# Starts one fAIrewall role on $PORT. See the Dockerfile for the roles.
set -e
PORT="${PORT:-8000}"
case "${FAIREWALL_ROLE:-sdk-gateway}" in
  lab)
    exec python -m fairewall.lab --host 0.0.0.0 --port "$PORT" ;;
  migrate)
    exec python -m fairewall.lab --migrate ;;
  gateway)
    # Shared state (sessions, freezes, approvals, audit chain) in Cloud SQL via FAIREWALL_DATABASE_URL.
    exec fairewall serve --host 0.0.0.0 --port "$PORT" ${FAIREWALL_POLICY:+--policy "$FAIREWALL_POLICY"} ;;
  control)
    exec fairewall control-plane --host 0.0.0.0 --port "$PORT" \
         --db "${FAIREWALL_DATABASE_URL:?FAIREWALL_DATABASE_URL is required}" ;;
  anchor)
    exec python -m fairewall.lab --anchor ;;
  sdk-gateway|*)
    exec python -m uvicorn fairewall.server:app --host 0.0.0.0 --port "$PORT" \
         --proxy-headers --forwarded-allow-ips "*" ;;
esac
