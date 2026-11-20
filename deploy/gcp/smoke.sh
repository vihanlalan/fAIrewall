#!/usr/bin/env bash
# Usage: LAB_URL=https://your-lab.run.app ./deploy/gcp/smoke.sh
set -euo pipefail
exec python3 "$(dirname "$0")/smoke.py"
