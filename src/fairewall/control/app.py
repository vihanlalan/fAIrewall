"""fAIrewall control plane: one place to run policy for many gateways.

Gateways register once, then sync every few seconds. Operators use the
dashboard (``/``) or this API to:

  * version policies and see what a change would do against real traffic;
  * deploy a version to an environment (staging, production), in shadow mode
    first if they like, then promote it, or roll back;
  * see every gateway's health, and which ones drifted from their policy;
  * read blocked and held calls from the whole fleet in one feed;
  * stop agents fleet-wide with the kill switch.
"""

from __future__ import annotations

import hmac
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from fastapi import FastAPI, Header, HTTPException, status
    from fastapi.responses import HTMLResponse
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover
    raise ImportError("The control plane requires `pip install fairewall[proxy]`") from exc

from ..policy import Policy
from ..report import build_diff
from .store import ControlError, ControlStore

_DASHBOARD = Path(__file__).with_name("dashboard.html")

# Gateways sync every POLL_SECONDS; one missing three syncs in a row is offline.
POLL_SECONDS = 10
OFFLINE_AFTER = 3 * POLL_SECONDS
# Cap on events accepted per sync, so one gateway cannot flood the store.
MAX_EVENTS_PER_SYNC = 1000


# ---------------------------------------------------------------- payloads

class RegisterGateway(BaseModel):
    name: str
    environment: str = "production"


class NewVersion(BaseModel):
    name: str
    body: Dict[str, Any]
    note: str = ""


class VersionRef(BaseModel):
    name: str
    version: int


class Compare(BaseModel):
    base: Optional[VersionRef] = None
    # Compare against a stored version, or an unsaved draft body.
    target: Optional[VersionRef] = None
    draft: Optional[Dict[str, Any]] = None
    # Replay recent decisions from this environment (all gateways if omitted).
    environment: Optional[str] = None
    limit: int = 2000


class Deploy(BaseModel):
    policy: str
    version: int
    shadow: bool = False


class Promote(BaseModel):
    source: str = "staging"
    shadow: bool = False


class Freeze(BaseModel):
    scope: str = "all"
    target: Optional[str] = None
    reason: str = ""


class SyncPayload(BaseModel):
    report: Dict[str, Any] = Field(default_factory=dict)
    log_id: str = ""
    events: List[Dict[str, Any]] = Field(default_factory=list)
    sent_up_to: Optional[int] = None


# ------------------------------------------------------------------ health

def gateway_health(gw: Dict[str, Any], env: Dict[str, Any], now: float) -> Dict[str, Any]:
    """Score one gateway out of 100 from things that can be checked, and say why.

    online 40 · running the assigned policy and mode 25 · audit chain intact 15 ·
    API key set 10 · separate reviewer key 10.
    """
    report = gw.get("report") or {}
    checks = []

    seen = gw.get("last_seen")
    online = bool(seen) and now - seen <= OFFLINE_AFTER
    checks.append(("online", 40, online,
                   "Online" if online else ("Never connected" if not seen else
                                            "Offline: last seen %ds ago" % int(now - seen))))

    if not env.get("fingerprint"):
        checks.append(("in_sync", 25, False,
                       "No policy deployed to %s: the gateway runs its local policy" % gw["environment"]))
    elif report.get("fingerprint") != env["fingerprint"]:
        checks.append(("in_sync", 25, False, "Drift: running %s, assigned %s v%s (%s)" % (
            (report.get("fingerprint") or "unknown")[:8], env["policy"], env["version"],
            env["fingerprint"][:8])))
    elif bool(report.get("shadow")) != bool(env.get("shadow")):
        checks.append(("in_sync", 25, False, "Mode drift: gateway is %s, environment says %s" % (
            "shadow" if report.get("shadow") else "enforcing",
            "shadow" if env.get("shadow") else "enforcing")))
    else:
        checks.append(("in_sync", 25, True, "Running %s v%s%s" % (
            env["policy"], env["version"], " (shadow)" if env.get("shadow") else "")))

    chain_ok = report.get("chain_valid", True) is not False
    checks.append(("audit_chain", 15, chain_ok,
                   "Audit chain intact" if chain_ok else "Audit chain BROKEN: records were altered"))
    auth = bool(report.get("auth_required"))
    checks.append(("api_key", 10, auth, "API key required" if auth else "No API key: open access"))
    rev = bool(report.get("separate_reviewer_key"))
    checks.append(("reviewer_key", 10, rev, "Separate reviewer key" if rev else
                   "No separate reviewer key: agents could approve their own calls"))

    if not seen:
        # Nothing reported yet: only "never connected" is known.
        checks = checks[:1] + [(c[0], c[1], False, "Unknown until first sync") for c in checks[1:]]
    score = sum(weight for _, weight, ok, _ in checks if ok)
    return {"score": score, "online": online,
            "checks": [{"id": cid, "weight": w, "ok": ok, "detail": d} for cid, w, ok, d in checks],
            "issues": [d for _, _, ok, d in checks if not ok],
            "frozen": bool(report.get("freezes"))}


def _flatten(value: Any, prefix: str = "") -> Dict[str, Any]:
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            out.update(_flatten(v, "%s.%s" % (prefix, k) if prefix else str(k)))
        return out or {prefix: {}}
    return {prefix: value}


def field_changes(old: Dict[str, Any], new: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every setting that differs between two policies, as path / before / after."""
    a, b = _flatten(old), _flatten(new)
    out = []
    for path in sorted(set(a) | set(b)):
        if a.get(path, "<absent>") != b.get(path, "<absent>"):
            out.append({"path": path, "before": a.get(path, None), "after": b.get(path, None),
                        "kind": "added" if path not in a else "removed" if path not in b else "changed"})
    return out


# --------------------------------------------------------------------- app

def create_control_app(store: Optional[ControlStore] = None, db_path: Optional[str] = None,
                       admin_key: Optional[str] = None) -> FastAPI:
    """Build the control-plane app.

    admin_key: required on every operator endpoint (``Authorization: Bearer``
        or ``X-API-Key``). Falls back to ``FAIREWALL_ADMIN_KEY``. Without one
        the API is open, which is for local trials only.
    """
    store = store or ControlStore(db_path or os.environ.get("FAIREWALL_CP_DB", ":memory:"))
    key = admin_key or os.environ.get("FAIREWALL_ADMIN_KEY")
    app = FastAPI(title="fAIrewall control plane", version="0.2.0")
    app.state.store = store

    def _supplied(authorization: Optional[str], x_api_key: Optional[str]) -> Optional[str]:
        if authorization and authorization.lower().startswith("bearer "):
            return authorization[7:].strip()
        return x_api_key

    def admin(authorization: Optional[str], x_api_key: Optional[str]) -> None:
        if not key:
            return
        supplied = _supplied(authorization, x_api_key)
        if not (supplied and hmac.compare_digest(supplied, key)):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Admin key required (Authorization: Bearer <key>).")

    def actor(x_actor: Optional[str]) -> str:
        return (x_actor or "admin").strip()[:100] or "admin"

    def guard(fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ControlError as exc:
            code = 404 if str(exc).startswith("No ") else 400
            raise HTTPException(status_code=code, detail=str(exc))

    def envs_by_name() -> Dict[str, Dict[str, Any]]:
        return {e["name"]: e for e in store.list_environments()}

    def gateways_with_health() -> List[Dict[str, Any]]:
        now, envs = time.time(), envs_by_name()
        out = []
        for gw in store.list_gateways():
            env = envs.get(gw["environment"]) or store.get_environment(gw["environment"])
            counts = store.action_counts(gw["id"], now - 3600)
            out.append(dict(gw, health=gateway_health(gw, env, now), last_hour=counts))
        return out

    # --------------------------------------------------------------- public

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard() -> HTMLResponse:
        return HTMLResponse(_DASHBOARD.read_text(encoding="utf-8"))

    @app.get("/health")
    async def health() -> Dict[str, Any]:
        return {"status": "ok", "service": "fairewall-control-plane", "version": "0.2.0"}

    @app.get("/cp/v1/info")
    async def info() -> Dict[str, Any]:
        return {"auth_required": bool(key), "poll_seconds": POLL_SECONDS}

    # -------------------------------------------------------------- gateway

    @app.post("/cp/v1/agent/sync")
    async def agent_sync(payload: SyncPayload,
                         authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        """A gateway's heartbeat. Authenticated by its own token, which identifies it."""
        token = _supplied(authorization, None)
        gw = store.gateway_for_token(token or "")
        if gw is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Unknown gateway token.")
        report = {k: payload.report.get(k) for k in (
            "fingerprint", "policy_version", "shadow", "auth_required", "separate_reviewer_key",
            "chain_valid", "chain_checked", "audit_head", "freezes", "detectors", "boot_id",
            "started_at")}
        events = payload.events[:MAX_EVENTS_PER_SYNC]
        store.record_sync(gw["id"], report, events, payload.log_id)
        env = store.get_environment(gw["environment"])
        policy = None
        if env.get("policy"):
            version = store.get_version(env["policy"], env["version"])
            policy = {"name": env["policy"], "version": env["version"],
                      "fingerprint": version["fingerprint"], "shadow": env["shadow"],
                      "body": version["body"]}
        return {
            "gateway": {"id": gw["id"], "name": gw["name"], "environment": gw["environment"]},
            "policy": policy,
            "freezes": store.fleet_freezes(),
            "acked_seq": store.last_seq(gw["id"], payload.log_id),
            "poll_seconds": POLL_SECONDS,
        }

    # ------------------------------------------------------------- overview

    @app.get("/cp/v1/overview")
    async def overview(authorization: Optional[str] = Header(None),
                       x_api_key: Optional[str] = Header(None)) -> Dict[str, Any]:
        admin(authorization, x_api_key)
        gws = gateways_with_health()
        scores = [g["health"]["score"] for g in gws]
        hour_ago = time.time() - 3600
        blocked = sum(g["last_hour"].get("block", 0) for g in gws)
        review = sum(g["last_hour"].get("flag", 0) for g in gws)
        allowed = sum(g["last_hour"].get("allow", 0) for g in gws)
        issues: List[str] = []
        offline = [g["name"] for g in gws if not g["health"]["online"]]
        drifted = [g["name"] for g in gws
                   if any(c["id"] == "in_sync" and not c["ok"] for c in g["health"]["checks"])
                   and g["last_seen"]]
        if offline:
            issues.append("%d gateway(s) offline: %s" % (len(offline), ", ".join(offline)))
        if drifted:
            issues.append("%d gateway(s) not on their assigned policy: %s" % (len(drifted), ", ".join(drifted)))
        broken = [g["name"] for g in gws if g["report"].get("chain_valid") is False]
        if broken:
            issues.append("Audit chain broken on: " + ", ".join(broken))
        return {
            "fleet_score": round(sum(scores) / len(scores)) if scores else None,
            "gateways": gws, "environments": store.list_environments(),
            "freezes": store.fleet_freezes(), "issues": issues,
            "last_hour": {"allow": allowed, "review": review, "block": blocked,
                          "since": hour_ago},
        }

    # ------------------------------------------------------------- gateways

    @app.get("/cp/v1/gateways")
    async def list_gateways(authorization: Optional[str] = Header(None),
                            x_api_key: Optional[str] = Header(None)) -> Dict[str, Any]:
        admin(authorization, x_api_key)
        return {"gateways": gateways_with_health()}

    @app.post("/cp/v1/gateways")
    async def register_gateway(payload: RegisterGateway,
                               authorization: Optional[str] = Header(None),
                               x_api_key: Optional[str] = Header(None),
                               x_actor: Optional[str] = Header(None)) -> Dict[str, Any]:
        """Register a gateway. The token in the reply is shown once and stored only as a hash."""
        admin(authorization, x_api_key)
        gw, token = guard(store.register_gateway, payload.name, payload.environment, actor(x_actor))
        return {"gateway": gw, "token": token}

    @app.delete("/cp/v1/gateways/{gateway_id}")
    async def remove_gateway(gateway_id: str, authorization: Optional[str] = Header(None),
                             x_api_key: Optional[str] = Header(None),
                             x_actor: Optional[str] = Header(None)) -> Dict[str, Any]:
        admin(authorization, x_api_key)
        guard(store.remove_gateway, gateway_id, actor(x_actor))
        return {"removed": gateway_id}

    # ------------------------------------------------------------- policies

    @app.get("/cp/v1/policies")
    async def list_policies(authorization: Optional[str] = Header(None),
                            x_api_key: Optional[str] = Header(None)) -> Dict[str, Any]:
        admin(authorization, x_api_key)
        return {"versions": store.list_versions(), "environments": store.list_environments()}

    @app.get("/cp/v1/policies/{name}/{version}")
    async def get_policy(name: str, version: int, authorization: Optional[str] = Header(None),
                         x_api_key: Optional[str] = Header(None)) -> Dict[str, Any]:
        admin(authorization, x_api_key)
        return guard(store.get_version, name, version)

    @app.post("/cp/v1/policies")
    async def create_policy_version(payload: NewVersion,
                                    authorization: Optional[str] = Header(None),
                                    x_api_key: Optional[str] = Header(None),
                                    x_actor: Optional[str] = Header(None)) -> Dict[str, Any]:
        """Store a new version. It does nothing until deployed to an environment."""
        admin(authorization, x_api_key)
        return guard(store.create_version, payload.name, payload.body, actor(x_actor), payload.note)

    @app.post("/cp/v1/policies/compare")
    async def compare(payload: Compare, authorization: Optional[str] = Header(None),
                      x_api_key: Optional[str] = Header(None)) -> Dict[str, Any]:
        """What changes between two policies: settings, and verdicts on real recent traffic.

        The replay uses the decisions gateways sent in, with arguments as the
        gateways logged them (secret-looking fields masked, long text cut at
        300 characters), so it is a close estimate rather than an exact rerun.
        """
        admin(authorization, x_api_key)
        if payload.base is None:
            raise HTTPException(status_code=400, detail="base is required.")
        base = guard(store.get_version, payload.base.name, payload.base.version)
        if payload.target is not None:
            target_body = guard(store.get_version, payload.target.name, payload.target.version)["body"]
        elif payload.draft is not None:
            try:
                target_body = Policy.from_dict(payload.draft).to_dict()
            except (ValueError, TypeError, KeyError) as exc:
                raise HTTPException(status_code=400, detail="Invalid draft policy: %s" % exc)
        else:
            raise HTTPException(status_code=400, detail="Give a target version or a draft body.")
        events = store.events(limit=max(1, min(payload.limit, 5000)), event="tool_call_inspected",
                              environment=payload.environment)
        events = [e for e in reversed(events) if e["tool"] and e["tool"] != "<chat>"]
        records = [{"tool": e["tool"], "arguments": e["arguments"],
                    "session_id": "%s:%s" % (e["gateway_id"], e["session_id"])} for e in events]
        replay = build_diff(records, Policy.from_dict(base["body"]), Policy.from_dict(target_body),
                            max_examples=15)
        return {"settings": field_changes(base["body"], target_body), "replay": replay,
                "replayed_from": payload.environment or "all environments",
                "events_replayed": len(records)}

    # --------------------------------------------------------- environments

    @app.get("/cp/v1/environments")
    async def environments(authorization: Optional[str] = Header(None),
                           x_api_key: Optional[str] = Header(None)) -> Dict[str, Any]:
        admin(authorization, x_api_key)
        return {"environments": store.list_environments()}

    @app.post("/cp/v1/environments/{environment}/deploy")
    async def deploy(environment: str, payload: Deploy,
                     authorization: Optional[str] = Header(None),
                     x_api_key: Optional[str] = Header(None),
                     x_actor: Optional[str] = Header(None)) -> Dict[str, Any]:
        """Assign a version to an environment. Also how you roll back: deploy the old one."""
        admin(authorization, x_api_key)
        return guard(store.deploy, environment, payload.policy, payload.version, payload.shadow,
                     actor(x_actor))

    @app.post("/cp/v1/environments/{environment}/promote")
    async def promote(environment: str, payload: Promote,
                      authorization: Optional[str] = Header(None),
                      x_api_key: Optional[str] = Header(None),
                      x_actor: Optional[str] = Header(None)) -> Dict[str, Any]:
        """Give *environment* whatever *source* runs (e.g. promote staging to production)."""
        admin(authorization, x_api_key)
        return guard(store.promote, payload.source, environment, actor(x_actor), payload.shadow)

    # --------------------------------------------------------------- events

    @app.get("/cp/v1/events")
    async def events(limit: int = 100, gateway: Optional[str] = None,
                     environment: Optional[str] = None, actions: Optional[str] = None,
                     authorization: Optional[str] = Header(None),
                     x_api_key: Optional[str] = Header(None)) -> Dict[str, Any]:
        """Fleet-wide decision feed. ?actions=block,flag for alerts only."""
        admin(authorization, x_api_key)
        wanted = [a.strip() for a in actions.split(",") if a.strip()] if actions else None
        return {"events": store.events(limit=limit, gateway_id=gateway, actions=wanted,
                                       environment=environment)}

    # ---------------------------------------------------------- kill switch

    @app.get("/cp/v1/killswitch")
    async def killswitch(authorization: Optional[str] = Header(None),
                         x_api_key: Optional[str] = Header(None)) -> Dict[str, Any]:
        admin(authorization, x_api_key)
        return {"freezes": store.fleet_freezes()}

    @app.post("/cp/v1/killswitch/freeze")
    async def fleet_freeze(payload: Freeze, authorization: Optional[str] = Header(None),
                           x_api_key: Optional[str] = Header(None),
                           x_actor: Optional[str] = Header(None)) -> Dict[str, Any]:
        """Stop agents on every gateway. Each applies it on its next sync (within ~10 s)."""
        admin(authorization, x_api_key)
        record = guard(store.fleet_freeze, payload.scope, payload.target, payload.reason, actor(x_actor))
        return {"freeze": record, "freezes": store.fleet_freezes()}

    @app.post("/cp/v1/killswitch/unfreeze")
    async def fleet_unfreeze(payload: Freeze, authorization: Optional[str] = Header(None),
                             x_api_key: Optional[str] = Header(None),
                             x_actor: Optional[str] = Header(None)) -> Dict[str, Any]:
        admin(authorization, x_api_key)
        if not store.fleet_unfreeze(payload.scope, payload.target, actor(x_actor)):
            raise HTTPException(status_code=404, detail="Nothing is frozen at that scope.")
        return {"freezes": store.fleet_freezes()}

    # -------------------------------------------------------------- history

    @app.get("/cp/v1/changes")
    async def changes(limit: int = 100, authorization: Optional[str] = Header(None),
                      x_api_key: Optional[str] = Header(None)) -> Dict[str, Any]:
        """Who changed what, newest first: versions, deploys, gateways, freezes."""
        admin(authorization, x_api_key)
        return {"changes": store.changes(limit)}

    return app
