"""HTTP surface of the fAIrewall Lab. The browser holds only its own sandbox's capability tokens."""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from . import fixtures as fx
from .runtime import Lab, LabError

PAGE = Path(__file__).with_name("lab.html")


class RunIn(BaseModel):
    chapter: Optional[int] = None
    variant: bool = False
    kind: str = "operator"
    text: str = Field("", max_length=4000)
    fixture: str = ""
    source: str = "recorded"


class ReviewIn(BaseModel):
    approve: bool


class LabelIn(BaseModel):
    verdict: str
    note: str = ""


class ScopeIn(BaseModel):
    tools: Optional[list] = None
    args: Optional[Dict[str, list]] = None
    destinations: Optional[list] = None
    max_spend: Optional[float] = None


class FreezeIn(BaseModel):
    scope: str = "principal"
    run_id: str = ""


class CandidateIn(BaseModel):
    max_spend_per_transaction: Optional[float] = None
    max_spend_per_session: Optional[float] = None
    review_above: Optional[float] = None


def create_lab_app(lab: Lab) -> FastAPI:
    app = FastAPI(title="fAIrewall Lab", version="1.0", docs_url=None, redoc_url=None)
    from ..ui import mount_theme
    mount_theme(app)
    created: Dict[str, list] = {}
    created_lock = threading.Lock()

    def ws_for(authorization: Optional[str], need: str) -> str:
        token = (authorization or "").split(" ", 1)[-1].strip() if authorization else ""
        try:
            return lab.authorize(token, need)
        except LabError as exc:
            raise HTTPException(exc.status, str(exc))

    def call(fn, *args, **kw):
        try:
            return fn(*args, **kw)
        except LabError as exc:
            raise HTTPException(exc.status, str(exc))

    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def page() -> HTMLResponse:
        return HTMLResponse(PAGE.read_text(encoding="utf-8"))

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> Dict[str, Any]:
        return {"ok": True}

    @app.get("/api/status")
    def status() -> Dict[str, Any]:
        return lab.status()

    @app.get("/api/chapters")
    def chapters() -> Dict[str, Any]:
        return {"chapters": [{k: c.get(k) for k in ("id", "slug", "title", "teaches", "sdk", "scope", "input",
                                                     "followups")} | {"has_variant": bool(c.get("variant")),
                                                                      "variant_label": (c.get("variant") or {}).get("label")}
                             for c in fx.CHAPTERS],
                "checks": [{"id": v["id"], "title": v["title"], "rule": v["rule"]} for v in fx.VARIANTS],
                "fixtures": {"email": {k: v[1] for k, v in fx.EMAILS.items()},
                             "website": {k: v[1] for k, v in fx.WEBSITES.items()},
                             "transcript": {k: v[1] for k, v in fx.TRANSCRIPTS.items()}}}

    @app.post("/api/workspaces")
    def new_workspace(request: Request) -> Dict[str, Any]:
        ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "?").split(",")[0]
        now = time.time()
        with created_lock:
            recent = [t for t in created.get(ip, []) if now - t < 3600]
            if len(recent) >= int(os.environ.get("LAB_WORKSPACES_PER_IP_HOUR", "20")):
                raise HTTPException(429, "Too many new sandboxes from this address; try again later.")
            created[ip] = recent + [now]
        return lab.create_workspace()

    @app.post("/api/runs")
    def start_run(body: RunIn, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        ws = ws_for(authorization, "propose")
        return call(lab.start_run, ws, kind=body.kind, text=body.text, fixture=body.fixture,
                    chapter=body.chapter, variant=body.variant, source=body.source)

    @app.get("/api/runs")
    def runs(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        return {"runs": lab.runs(ws_for(authorization, "read"))}

    @app.get("/api/runs/{run_id}")
    def run(run_id: str, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        return call(lab.run_view, ws_for(authorization, "read"), run_id)

    @app.post("/api/runs/{run_id}/scope")
    def scope(run_id: str, body: ScopeIn, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        token = (authorization or "").split(" ", 1)[-1]
        try:
            ws, reviewer = lab.authorize(token, "review"), True
        except LabError:
            ws, reviewer = ws_for(authorization, "propose"), False
        return call(lab.set_scope, ws, run_id, body.model_dump(exclude_none=True), reviewer=reviewer)

    @app.get("/api/inbox")
    def inbox(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        return lab.inbox(ws_for(authorization, "read"))

    @app.post("/api/actions/{action_id}/review")
    def review(action_id: str, body: ReviewIn, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        return call(lab.review, ws_for(authorization, "review"), action_id, body.approve)

    @app.post("/api/cases/{case_id}/label")
    def label(case_id: str, body: LabelIn, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        return call(lab.label, ws_for(authorization, "review"), case_id, body.verdict, body.note)

    @app.post("/api/cases/{case_id}/revoke")
    def revoke(case_id: str, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        return call(lab.revoke, ws_for(authorization, "review"), case_id, "revoked from the Lab")

    @app.post("/api/checks/{check_id}")
    def check(check_id: str, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        return call(lab.run_variant, ws_for(authorization, "propose"), check_id)

    @app.post("/api/killswitch/freeze")
    def freeze(body: FreezeIn, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        return call(lab.freeze, ws_for(authorization, "review"), body.scope, body.run_id)

    @app.post("/api/killswitch/unfreeze")
    def unfreeze(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        return call(lab.unfreeze, ws_for(authorization, "review"))

    @app.get("/api/fleet")
    def fleet(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        return lab.fleet(ws_for(authorization, "read"))

    @app.post("/api/rollout/compare")
    def compare(body: CandidateIn, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        return call(lab.rollout_compare, ws_for(authorization, "review"), body.model_dump(exclude_none=True))

    @app.post("/api/rollout/{action}")
    def rollout(action: str, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        return call(lab.rollout_set, ws_for(authorization, "review"), action)

    @app.get("/api/evidence")
    def evidence(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        return lab.evidence(ws_for(authorization, "read"))

    @app.post("/api/evidence/tamper")
    def tamper(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        ws_for(authorization, "read")
        return lab.tamper("")

    @app.get("/api/trace")
    def trace(run: str = "", action: str = "", authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        return {"events": lab.trace(ws_for(authorization, "read"), run_id=run or None, action_id=action or None)}

    @app.get("/api/ledger")
    def ledger(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        ws = ws_for(authorization, "read")
        return lab.mask(ws, lab.ledger.state(ws))

    @app.get("/api/limits")
    def limits() -> Dict[str, Any]:
        return lab.limits_view()

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": "Internal error: %s" % type(exc).__name__})

    return app
