"""Gemini as a thin, replaceable model adapter. fAIrewall stays in charge of actions.

What this module does, and deliberately does not do:

* Function declarations are built from the same tool definitions fAIrewall's
  registry validates against, so the model and the gateway share one schema.
* Automatic function calling is OFF. The model only *proposes* calls; the
  agent runner submits each one to the ActionStore, which decides and runs it.
* Model turns are kept exactly as Gemini returned them (including thought
  signatures), serialised as JSON so a paused run survives a restart.

Two clients share one interface and one content format (the JSON form of
``google.genai.types.Content``):

* ``GeminiClient``: live calls. Needs ``pip install fairewall[gemini]`` and
  ``GEMINI_API_KEY``; the model comes from ``GEMINI_MODEL``.
* ``RecordedClient``: replays scripted model turns, for demos without network
  and for tests. Runs it produces are labelled ``source="recorded"``.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

DEFAULT_MODEL = "gemini-2.5-flash"
# Treated as "no key configured", so a copied .env.example never makes live calls.
PLACEHOLDER_KEYS = {"", "your-gemini-api-key", "changeme", "placeholder"}

# JSON Schema keywords passed to the model. The full schema (with
# additionalProperties etc.) is still enforced by the ActionStore validator.
_MODEL_SCHEMA_KEYS = {"type", "properties", "required", "description", "enum", "items",
                      "minimum", "maximum", "minLength", "maxLength", "pattern", "format",
                      "minItems", "maxItems", "nullable", "title"}


class ModelError(Exception):
    """The model call failed. ``kind`` is "timeout", "api_error" or "not_configured"."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass
class ToolCall:
    name: str
    args: Dict[str, Any]
    id: Optional[str] = None


@dataclass
class ModelResponse:
    content: Optional[Dict[str, Any]]      # the model turn, to append to history as-is
    calls: List[ToolCall] = field(default_factory=list)
    text: str = ""
    model: str = ""
    latency_ms: float = 0.0
    finish_reason: Optional[str] = None
    unsupported: List[str] = field(default_factory=list)   # part types we cannot act on


# ----------------------------------------------------------------- schema

def _model_schema(schema: Any) -> Any:
    if isinstance(schema, dict):
        out = {}
        for key, value in schema.items():
            if key not in _MODEL_SCHEMA_KEYS:
                continue
            if key == "properties" and isinstance(value, dict):
                out[key] = {name: _model_schema(sub) for name, sub in value.items()}
            else:
                out[key] = _model_schema(value)
        return out
    if isinstance(schema, list):
        return [_model_schema(v) for v in schema]
    return schema


def declarations_for(definitions: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Gemini function declarations from registered MCP-style tool definitions."""
    return [{"name": d["name"], "description": d.get("description", ""),
             "parameters": _model_schema(d["inputSchema"])} for d in definitions]


def normalize_args(value: Any) -> Any:
    """Turn integral floats into ints. Gemini returns JSON numbers through a
    protobuf Struct, so 4000 can arrive as 4000.0; the ledger wants integers."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {k: normalize_args(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize_args(v) for v in value]
    return value


# ------------------------------------------------------- shared content form

def user_content(text: str) -> Dict[str, Any]:
    return {"role": "user", "parts": [{"text": text}]}


def tool_results_content(results: Sequence["tuple[ToolCall, Dict[str, Any]]"]) -> Dict[str, Any]:
    """One user turn answering every call of the previous model turn, in order."""
    parts = []
    for call, payload in results:
        response: Dict[str, Any] = {"name": call.name, "response": payload}
        if call.id:
            response["id"] = call.id
        parts.append({"function_response": response})
    return {"role": "user", "parts": parts}


def parse_turn(content: Optional[Dict[str, Any]]) -> "tuple[List[ToolCall], str, List[str]]":
    """Calls, visible text and unsupported part types from a stored model turn."""
    calls: List[ToolCall] = []
    texts: List[str] = []
    unsupported: List[str] = []
    for part in (content or {}).get("parts") or []:
        if part.get("function_call"):
            fc = part["function_call"]
            calls.append(ToolCall(name=fc.get("name") or "", args=normalize_args(fc.get("args") or {}),
                                  id=fc.get("id")))
        elif part.get("text") is not None:
            if not part.get("thought"):
                texts.append(part["text"])
        else:
            kinds = [k for k, v in part.items() if v is not None and k not in ("thought_signature", "thought")]
            unsupported.extend(kinds)
    return calls, "".join(texts), unsupported


# ------------------------------------------------------------------ live

class GeminiClient:
    """Live Gemini, with automatic function calling disabled."""

    source = "live"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None,
                 timeout_s: float = 30.0, *, vertex: Optional[bool] = None,
                 project: Optional[str] = None, location: Optional[str] = None) -> None:
        """Gemini through an API key (Google AI Studio) or Vertex AI.

        Vertex AI needs no key: it uses Application Default Credentials (on
        Cloud Run, the service's own identity, which needs roles/aiplatform.user).
        It is chosen with ``vertex=True`` or GOOGLE_GENAI_USE_VERTEXAI=true, with
        GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_LOCATION (default asia-south1).
        """
        try:
            from google import genai
            from google.genai import types
        except ImportError as exc:  # pragma: no cover - env dependent
            raise ModelError("not_configured", "Live runs need `pip install fairewall[gemini]`.") from exc
        self._types = types
        self.model = (model or os.environ.get("GEMINI_MODEL") or DEFAULT_MODEL).strip()
        if vertex is None:
            vertex = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "").lower() in ("1", "true")
        http = types.HttpOptions(timeout=int(timeout_s * 1000))
        if vertex:
            project = project or os.environ.get("GOOGLE_CLOUD_PROJECT")
            location = location or os.environ.get("GOOGLE_CLOUD_LOCATION") or "asia-south1"
            if not project:
                raise ModelError("not_configured", "Vertex AI needs GOOGLE_CLOUD_PROJECT.")
            try:
                self._client = genai.Client(vertexai=True, project=project, location=location,
                                            http_options=http)
            except Exception as exc:  # no Application Default Credentials, for example
                raise ModelError("not_configured", "Vertex AI unavailable: %s" % exc) from exc
            self.backend = "vertex:%s" % location
            return
        key = (api_key if api_key is not None else os.environ.get("GEMINI_API_KEY", "")).strip()
        if key.lower() in PLACEHOLDER_KEYS:
            raise ModelError("not_configured", "GEMINI_API_KEY is not set; live runs are unavailable.")
        self._client = genai.Client(api_key=key, http_options=http)
        self.backend = "gemini-api"

    def generate(self, history: List[Dict[str, Any]], *, tools: List[Dict[str, Any]], system: str,
                 scenario: Optional[str] = None) -> ModelResponse:
        types = self._types
        contents = [types.Content.model_validate(c) for c in history]
        config = types.GenerateContentConfig(
            system_instruction=system,
            tools=[types.Tool(function_declarations=[
                types.FunctionDeclaration(name=t["name"], description=t["description"],
                                          parameters_json_schema=t["parameters"]) for t in tools])],
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
            tool_config=types.ToolConfig(
                function_calling_config=types.FunctionCallingConfig(mode="AUTO")),
        )
        started = time.perf_counter()
        try:
            resp = self._client.models.generate_content(model=self.model, contents=contents, config=config)
        except Exception as exc:
            text = "%s: %s" % (type(exc).__name__, str(exc)[:300])
            kind = "timeout" if "timeout" in text.lower() or "timed out" in text.lower() else "api_error"
            raise ModelError(kind, text) from exc
        latency = (time.perf_counter() - started) * 1000
        candidate = resp.candidates[0] if resp.candidates else None
        finish = str(candidate.finish_reason) if candidate and candidate.finish_reason else None
        if candidate is None or candidate.content is None or not candidate.content.parts:
            feedback = getattr(resp, "prompt_feedback", None)
            return ModelResponse(content=None, model=resp.model_version or self.model, latency_ms=latency,
                                 finish_reason=finish or (str(feedback.block_reason) if feedback and
                                                          feedback.block_reason else "empty"))
        content = json.loads(candidate.content.model_dump_json(exclude_none=True))
        calls, text, unsupported = parse_turn(content)
        return ModelResponse(content=content, calls=calls, text=text, unsupported=unsupported,
                             model=resp.model_version or self.model, latency_ms=latency,
                             finish_reason=finish)


# -------------------------------------------------------------- recorded

class RecordedClient:
    """Replays scripted model turns. Deterministic, so it survives restarts.

    ``scenarios`` maps a name to a list of steps, one per model turn:

      {"call": {"name": "refund", "args": {...}}}       a function call
      {"text": "..."}                                    a final answer
      {"text_by_outcome": {"executed": "...", ...}}      a final answer picked by
          the status of the last function response, formatted with its fields

    A scenario may have "match": a regex picking it from the user's message.
    """

    source = "recorded"

    def __init__(self, scenarios: Dict[str, Dict[str, Any]], model: str = "recorded-script") -> None:
        self.scenarios = scenarios
        self.model = model

    @classmethod
    def from_file(cls, path: str, **kw: Any) -> "RecordedClient":
        with open(path, "r", encoding="utf-8") as fh:
            return cls(json.load(fh), **kw)

    def pick(self, message: str) -> Optional[str]:
        for name, sc in self.scenarios.items():
            if sc.get("match") and re.search(sc["match"], message, re.IGNORECASE | re.DOTALL):
                return name
        return None

    def generate(self, history: List[Dict[str, Any]], *, tools: List[Dict[str, Any]], system: str,
                 scenario: Optional[str] = None) -> ModelResponse:
        started = time.perf_counter()
        steps = (self.scenarios.get(scenario or "") or {}).get("steps") or []
        turn = sum(1 for c in history if c.get("role") == "model")
        if turn >= len(steps):
            return ModelResponse(content=None, model=self.model, finish_reason="script_ended",
                                 latency_ms=(time.perf_counter() - started) * 1000)
        step = steps[turn]
        if "call" in step:
            part = {"function_call": {"name": step["call"]["name"], "args": step["call"].get("args", {}),
                                      "id": "rec-%d" % turn}}
        elif "text_by_outcome" in step:
            last = _last_response(history)
            options = step["text_by_outcome"]
            template = options.get(last.get("status", ""), options.get("default", ""))
            part = {"text": template.format_map(_Fields(last))}
        else:
            part = {"text": step.get("text", "")}
        content = {"role": "model", "parts": [part]}
        calls, text, _ = parse_turn(content)
        return ModelResponse(content=content, calls=calls, text=text, model=self.model,
                             latency_ms=(time.perf_counter() - started) * 1000, finish_reason="STOP")


class _Fields(dict):
    def __missing__(self, key: str) -> str:
        return ""


def _last_response(history: List[Dict[str, Any]]) -> Dict[str, Any]:
    for content in reversed(history):
        for part in content.get("parts") or []:
            if part.get("function_response"):
                return dict(part["function_response"].get("response") or {})
    return {}
