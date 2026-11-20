"""Authenticated stateless JSON-response MCP server for registered actions."""
from __future__ import annotations

import hmac
import uuid
from typing import Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel

from ..actions import ActionStore, canonical
from ..approvals import ApprovalError
from ..types import Principal


class ActionRequest(BaseModel):
    tool: str
    arguments: dict
    session: str
    idempotency_key: str


class Intake(BaseModel):
    session: str
    text: str


class Review(BaseModel):
    approve: bool


def create_action_app(store: ActionStore, agents: Dict[str, Principal], reviewers: Dict[str, str],
                      origins=()):
    """Mount standalone or with app.mount. Credential maps are trusted configuration."""
    if not agents or not reviewers or set(agents) & set(reviewers) or "" in {*agents, *reviewers}:
        raise ValueError("Configure separate nonempty agent and reviewer credentials")
    app = FastAPI()
    version = "2025-06-18"

    def identity(header, credentials):
        for key, who in credentials.items():
            if header and hmac.compare_digest(header.encode(), ("Bearer " + key).encode()):
                return who
        raise HTTPException(401, "Invalid credential")

    def submit(payload, principal):
        try:
            return store.submit(payload.tool, payload.arguments, payload.session,
                                principal, payload.idempotency_key)
        except ApprovalError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/actions")
    def execute(payload: ActionRequest, authorization: Optional[str] = Header(None)):
        return submit(payload, identity(authorization, agents))

    @app.post("/intake")
    def intake(payload: Intake, authorization: Optional[str] = Header(None)):
        return store.screen(payload.session, identity(authorization, agents), payload.text).to_dict()

    @app.get("/reviews")
    def pending(authorization: Optional[str] = Header(None)):
        identity(authorization, reviewers)
        return store.pending()

    @app.post("/reviews/{request_id}")
    def review(request_id: str, payload: Review, authorization: Optional[str] = Header(None)):
        reviewer = identity(authorization, reviewers)
        try:
            requester = store.get(request_id)["principal"]["id"]
            current = next((p for p in agents.values() if p.id == requester), None)
            return store.review(request_id, reviewer, payload.approve and current is not None,
                                current_principal=current)
        except ApprovalError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/actions/{request_id}")
    def status(request_id: str, authorization: Optional[str] = Header(None)):
        principal = identity(authorization, agents)
        try:
            result = store.get(request_id)
        except ApprovalError:
            raise HTTPException(404, "Unknown action")
        if result["principal"]["id"] != principal.id:
            raise HTTPException(404, "Unknown action")
        return result

    @app.post("/mcp")
    def rpc(body: dict, request: Request, authorization: Optional[str] = Header(None)):
        origin = request.headers.get("origin")
        if origin and origin not in origins:
            raise HTTPException(403, "Unrecognized origin")
        principal = identity(authorization, agents)
        rid = body.get("id")
        response = {"jsonrpc": "2.0", "id": rid}
        method = body.get("method")
        params = body.get("params", {})
        if body.get("jsonrpc") != "2.0" or not isinstance(method, str) or not isinstance(params, dict):
            return dict(response, error={"code": -32600, "message": "Invalid request"})
        if method != "initialize" and request.headers.get("mcp-protocol-version", version) != version:
            raise HTTPException(400, "Unsupported protocol version")
        if rid is None and method.startswith("notifications/"):
            return Response(status_code=202)
        if not isinstance(rid, (str, int)) or isinstance(rid, bool):
            return dict(response, error={"code": -32600, "message": "Request ID required"})
        if method == "initialize":
            result = {"protocolVersion": version, "capabilities": {"tools": {}},
                      "serverInfo": {"name": "fairewall", "version": "0.2.0"}}
        elif method == "tools/list":
            result = {"tools": [a.definition for a in store.actions.values()]}
        elif method == "ping":
            result = {}
        elif method == "tools/call":
            # Standard clients may set a stable idempotency key in request metadata.
            # JSON-RPC IDs are connection-local, so never use them as durable keys.
            meta = params.get("_meta", {})
            args = params.get("arguments", {})
            if not isinstance(meta, dict) or not isinstance(args, dict):
                return dict(response, error={"code": -32602, "message": "Invalid arguments"})
            token = meta.get("fairewall/idempotencyKey", uuid.uuid4().hex)
            session = meta.get("fairewall/session", "default")
            if not all(isinstance(x, str) and x for x in (token, session, params.get("name"))):
                return dict(response, error={"code": -32602, "message": "Invalid action metadata"})
            try:
                record = store.submit(params["name"], args, session, principal, token)
            except ApprovalError as exc:
                return dict(response, error={"code": -32602, "message": str(exc)})
            result = {"isError": record["status"] in ("blocked", "rejected", "expired", "uncertain", "cancelled"),
                      "content": [{"type": "text", "text": canonical(
                          {k: record[k] for k in ("id", "status", "result", "rules")})}]}
        else:
            return dict(response, error={"code": -32601, "message": "Unknown method"})
        return dict(response, result=result)

    return app
