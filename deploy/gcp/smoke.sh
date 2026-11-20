#!/usr/bin/env bash
# Smoke checks against a deployed Lab. Proves the live paths actually ran.
#   LAB_URL=https://fw-lab-xxxx.a.run.app ./deploy/gcp/smoke.sh
set -euo pipefail
: "${LAB_URL:?Set LAB_URL}"
J() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
say() { printf '\n\033[1;33m== %s\033[0m\n' "$*"; }

say "Status (what is live)"
curl -fsS "$LAB_URL/api/status" | J 'json.dumps(d, indent=1)'

T=$(curl -fsS -X POST "$LAB_URL/api/workspaces")
P=$(echo "$T" | J 'd["propose_token"]'); R=$(echo "$T" | J 'd["review_token"]')
post() { curl -fsS -X POST "$LAB_URL$1" -H "Authorization: Bearer $2" -H "Content-Type: application/json" -d "$3"; }

say "1. Deterministic block, Model Armor skipped"
post /api/runs "$P" '{"chapter":2}' | J '[(s.get("detector") or s["stage"], s["status"]) for e in d["trace"] if e["event"]=="submit" for s in e["stages"]]'

say "2. Routed to live Model Armor (untrusted website)"
post /api/runs "$P" '{"chapter":3,"variant":true}' | J '[(s["status"], s.get("provenance"), s.get("evidence",{}).get("filters")) for e in d["trace"] if e["event"]=="screen" for s in e["stages"] if s.get("detector")=="model_armor"]'

say "3. Learning: label, then the variant is blocked by memory"
CASE=$(post /api/runs "$P" '{"chapter":5}' | J 'd["detail"].get("case_id")')
post "/api/cases/$CASE/label" "$R" '{"verdict":"malicious"}' >/dev/null
post /api/runs "$P" '{"kind":"website","fixture":"courier-weak-variant"}' | J '(d["status"], [e["rule_ids"] for e in d["trace"] if e["event"]=="screen"])'

say "Live Gemini proposal"
post /api/runs "$P" '{"chapter":1,"source":"live"}' | J '(d["status"], d["agent"] and d["agent"]["source"], d["agent"] and d["agent"]["model"], d["agent"] and d["agent"]["model_latency_ms"])'

say "Two gateways observe a freeze"
post /api/killswitch/freeze "$R" '{}' | J '[(g["gateway"], g["mode"], g["observed"], g["propagation_ms"]) for g in d["gateways"]]'
post /api/killswitch/unfreeze "$R" '{}' >/dev/null

say "Evidence"
curl -fsS "$LAB_URL/api/evidence" -H "Authorization: Bearer $P" | J '(d["proof_check"], d["published"])'
echo; echo "Smoke checks done."
