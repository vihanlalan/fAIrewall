"""Google Cloud Model Armor as a fAIrewall tier-1 detector.

Model Armor is Google's managed screening API for LLM traffic. Its prompt
injection and jailbreak filter (plus the malicious-URL filter) becomes one more
scored detector here, so it slots into the same place as the local ones:

  * It runs only when the router escalates a call: a high-risk tool, a tainted
    session, untrusted content, or an ambiguous rule result. Clean low-risk
    calls never leave the process, so latency and per-token cost stay small.
  * It can only tighten a verdict. A Model Armor match becomes a FLAG or BLOCK
    finding (``detector.model_armor``); a "no match" never overrides a rule.
  * If Model Armor is unreachable, times out, or refuses the request, the
    detector raises. The router then fails closed on high-risk routes (BLOCK)
    and flags elsewhere, exactly as for a crashing local detector.

Setup (once per project):

    gcloud services enable modelarmor.googleapis.com
    gcloud auth application-default login          # or a service account
    # the caller needs roles/modelarmor.user on the template's project
    fairewall model-armor create-template --project P --location us-central1 \
        --template-id fairewall-pi

Then:

    fairewall serve --detector learned --detector model_armor \
        --model-armor-template projects/P/locations/us-central1/templates/fairewall-pi

or set MODEL_ARMOR_TEMPLATE (full resource name) or MODEL_ARMOR_PROJECT,
MODEL_ARMOR_LOCATION and MODEL_ARMOR_TEMPLATE_ID. For a quick test without
Application Default Credentials, MODEL_ARMOR_ACCESS_TOKEN can hold a token from
``gcloud auth print-access-token`` (it expires after about an hour).

Only the text of the call being screened is sent to Google, at most
MAX_DETECTOR_CHARS characters of it, and only on escalated calls.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..detectors import Detector, DetectorResult

SCOPE = "https://www.googleapis.com/auth/cloud-platform"
DEFAULT_LOCATION = "us-central1"
_TEMPLATE_NAME = re.compile(
    r"^projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)/templates/(?P<template>[^/]+)$")
_TEMPLATE_ID = re.compile(r"^[A-Za-z0-9_-]{1,63}$")

# Filters this detector reads, with the label a match produces.
FILTERS = {
    "pi_and_jailbreak": ("piAndJailbreakFilterResult", "prompt_injection"),
    "malicious_uris": ("maliciousUriFilterResult", "malicious_uri"),
}
DEFAULT_FILTERS = ("pi_and_jailbreak", "malicious_uris")

# Model Armor reports a match at the template's confidence setting, sometimes
# with the confidence it reached. Map that onto fAIrewall's score scale: with
# the default thresholds (flag 0.5, block 0.85) a HIGH-confidence match blocks
# and a lower one flags for review. A match with no confidence reported met
# the template's own bar, so it scores ``match_score`` (block by default).
CONFIDENCE_SCORES = {
    "HIGH": 0.95,
    "MEDIUM_AND_ABOVE": 0.75,
    "LOW_AND_ABOVE": 0.6,
    "DETECTION_CONFIDENCE_LEVEL_UNSPECIFIED": 0.6,
}

Transport = Callable[[str, bytes, Dict[str, str], float], Dict[str, Any]]


class ModelArmorError(RuntimeError):
    """Model Armor could not give a verdict. ``kind`` says why."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


def parse_template(template: Optional[str] = None, project: Optional[str] = None,
                   location: Optional[str] = None,
                   template_id: Optional[str] = None) -> Tuple[str, str, str]:
    """Resolve (project, location, template_id) from arguments, then env vars."""
    template = template or os.environ.get("MODEL_ARMOR_TEMPLATE")
    if template and "/" in template:
        m = _TEMPLATE_NAME.match(template.strip())
        if not m:
            raise ValueError("Model Armor template must look like "
                             "projects/PROJECT/locations/LOCATION/templates/TEMPLATE_ID")
        return m.group("project"), m.group("location"), m.group("template")
    project = project or os.environ.get("MODEL_ARMOR_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
    location = location or os.environ.get("MODEL_ARMOR_LOCATION") or DEFAULT_LOCATION
    template_id = template_id or template or os.environ.get("MODEL_ARMOR_TEMPLATE_ID")
    if not project or not template_id:
        raise ValueError(
            "Model Armor needs a template: pass --model-armor-template "
            "projects/P/locations/L/templates/T, or set MODEL_ARMOR_TEMPLATE, or set "
            "MODEL_ARMOR_PROJECT and MODEL_ARMOR_TEMPLATE_ID.")
    if not _TEMPLATE_ID.match(template_id):
        raise ValueError("Model Armor template IDs use up to 63 letters, digits, '_' or '-'")
    return project, location, template_id


def endpoint(location: str) -> str:
    # Sanitization is regional only; the global host serves floor settings.
    return f"https://modelarmor.{location}.rep.googleapis.com/v1"


class TokenSource:
    """Bearer tokens: a fixed token if given, else Application Default Credentials."""

    def __init__(self, token: Optional[str] = None) -> None:
        self._static = token or os.environ.get("MODEL_ARMOR_ACCESS_TOKEN") or None
        self._creds: Any = None
        self._lock = threading.Lock()

    def __call__(self) -> str:
        if self._static:
            return self._static
        with self._lock:
            if self._creds is None:
                try:
                    import google.auth  # type: ignore
                    from google.auth.exceptions import DefaultCredentialsError  # type: ignore
                except ImportError as exc:
                    raise ModelArmorError(
                        "not_configured",
                        "Model Armor needs google-auth (pip install 'fairewall[model-armor]') "
                        "or MODEL_ARMOR_ACCESS_TOKEN.") from exc
                try:
                    self._creds, _ = google.auth.default(scopes=[SCOPE])
                except DefaultCredentialsError as exc:
                    raise ModelArmorError(
                        "not_configured",
                        "No Google credentials found. Run `gcloud auth application-default "
                        "login`, set GOOGLE_APPLICATION_CREDENTIALS, or set "
                        "MODEL_ARMOR_ACCESS_TOKEN.") from exc
            if not self._creds.valid:
                from google.auth.transport.requests import Request  # type: ignore
                try:
                    self._creds.refresh(Request())
                except Exception as exc:
                    raise ModelArmorError("auth", f"Could not refresh Google credentials: {exc}") from exc
            return self._creds.token


def _http_post(url: str, body: bytes, headers: Dict[str, str], timeout: float) -> Dict[str, Any]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("error", {}).get("message", "")
        except Exception:
            pass
        kind = {400: "bad_request", 401: "auth", 403: "permission", 404: "not_found",
                429: "quota"}.get(exc.code, "api_error")
        hint = {
            "permission": " The caller needs roles/modelarmor.user and the Model Armor API "
                          "enabled on the template's project.",
            "not_found": " Check the template name and that its location matches.",
        }.get(kind, "")
        raise ModelArmorError(kind, f"Model Armor returned HTTP {exc.code}: {detail}{hint}".strip()) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ModelArmorError("unreachable", f"Model Armor unreachable: {exc}") from exc
    except ValueError as exc:
        raise ModelArmorError("api_error", "Model Armor returned a response that is not JSON") from exc


def _filter_entries(filter_results: Any) -> Dict[str, Any]:
    """filterResults is documented as an object; one sample shows a list."""
    if isinstance(filter_results, dict):
        return filter_results
    merged: Dict[str, Any] = {}
    if isinstance(filter_results, list):
        for item in filter_results:
            if isinstance(item, dict):
                merged.update(item)
    return merged


def score_response(data: Dict[str, Any], filters=DEFAULT_FILTERS,
                   match_score: float = 0.9) -> DetectorResult:
    """Turn a sanitizeUserPrompt response into a fAIrewall DetectorResult."""
    result = data.get("sanitizationResult")
    if not isinstance(result, dict):
        raise ModelArmorError("api_error", "Model Armor response has no sanitizationResult")
    invocation = result.get("invocationResult", "SUCCESS")
    if invocation not in ("SUCCESS", "INVOCATION_RESULT_UNSPECIFIED"):
        raise ModelArmorError("api_error", f"Model Armor invocation result: {invocation}")
    entries = _filter_entries(result.get("filterResults"))

    score, label = 0.0, "benign"
    matched: List[str] = []
    checked: Dict[str, str] = {}
    skipped: List[str] = []
    for key in filters:
        inner_key, match_label = FILTERS[key]
        inner = (entries.get(key) or {}).get(inner_key)
        if not isinstance(inner, dict):
            continue
        state = inner.get("matchState", "")
        execution = inner.get("executionState", "")
        checked[key] = state or execution
        if state == "EXECUTION_SKIPPED" or execution == "EXECUTION_SKIPPED":
            skipped.append(key)
            continue
        if state == "MATCH_FOUND":
            confidence = inner.get("confidenceLevel")
            s = CONFIDENCE_SCORES.get(confidence, match_score) if confidence else match_score
            matched.append(key + (f":{confidence}" if confidence else ""))
            if s > score:
                score, label = s, match_label

    evidence: Dict[str, Any] = {"filters": checked}
    if matched:
        evidence["matched"] = matched
    if skipped:
        evidence["skipped"] = skipped
        messages = [m.get("message") for m in inner_messages(result) if m.get("message")]
        if messages:
            evidence["skip_reason"] = messages[0][:200]
    version = ((result.get("sanitizationMetadata") or {}).get("filterVersionConfig") or {}).get("filterVersion")
    if version:
        evidence["filter_version"] = version
    return DetectorResult(score=score, label=label, evidence=evidence)


def inner_messages(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for entry in _filter_entries(result.get("filterResults")).values():
        if isinstance(entry, dict):
            for inner in entry.values():
                if isinstance(inner, dict):
                    out.extend(m for m in inner.get("messageItems", []) if isinstance(m, dict))
    return out


class ModelArmorDetector(Detector):
    """Prompt injection, jailbreak and malicious-URL screening via Model Armor.

    Every text goes to ``sanitizeUserPrompt``, the only endpoint that runs the
    injection filter, whether it is a user message, a retrieved document, a
    tool's output or a tool call's arguments: to the model they are all input.

    Model Armor itself returns "no match" for text under three words, and skips
    detection past its token limit; skips are reported in the finding evidence.
    Identical texts within ``cache_ttl_s`` are answered from a small cache, so a
    document re-read several times in one session is screened (and billed) once.
    """

    name = "model_armor"
    deep = True  # a remote, billed call: source sampling may skip it for trusted sources

    def __init__(self, template: Optional[str] = None, *, project: Optional[str] = None,
                 location: Optional[str] = None, template_id: Optional[str] = None,
                 token: Optional[str] = None, token_source: Optional[Callable[[], str]] = None,
                 timeout_s: float = 3.0, filters=DEFAULT_FILTERS, match_score: float = 0.9,
                 cache_size: int = 1024, cache_ttl_s: float = 300.0,
                 transport: Optional[Transport] = None) -> None:
        self.project, self.location, self.template_id = parse_template(
            template, project, location, template_id)
        unknown = [f for f in filters if f not in FILTERS]
        if unknown:
            raise ValueError(f"Unknown Model Armor filter(s) {unknown}; expected {sorted(FILTERS)}")
        self.filters = tuple(filters)
        self.match_score = float(match_score)
        self.timeout_s = float(os.environ.get("MODEL_ARMOR_TIMEOUT_S", timeout_s))
        self.template = (f"projects/{self.project}/locations/{self.location}"
                         f"/templates/{self.template_id}")
        self.url = f"{endpoint(self.location)}/{self.template}:sanitizeUserPrompt"
        self._tokens = token_source or TokenSource(token)
        self._post = transport or _http_post
        self._cache: "OrderedDict[str, Tuple[float, DetectorResult]]" = OrderedDict()
        self._cache_size, self._cache_ttl = cache_size, cache_ttl_s
        self._lock = threading.Lock()
        self.calls = 0

    def _cached(self, key: str) -> Optional[DetectorResult]:
        with self._lock:
            hit = self._cache.get(key)
            if hit and time.monotonic() - hit[0] < self._cache_ttl:
                self._cache.move_to_end(key)
                return hit[1]
            if hit:
                del self._cache[key]
        return None

    def _remember(self, key: str, result: DetectorResult) -> None:
        if self._cache_size <= 0:
            return
        with self._lock:
            self._cache[key] = (time.monotonic(), result)
            self._cache.move_to_end(key)
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)

    def detect(self, text: str) -> DetectorResult:
        text = text or ""
        if not text.strip():
            return DetectorResult(score=0.0, label="benign", evidence={"filters": {}, "empty": True})
        key = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        hit = self._cached(key)
        if hit is not None:
            return DetectorResult(hit.score, hit.label, {**hit.evidence, "cached": True})

        body = json.dumps({"userPromptData": {"text": text}}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self._tokens()}",
            "Content-Type": "application/json",
        }
        started = time.perf_counter()
        self.calls += 1
        data = self._post(self.url, body, headers, self.timeout_s)
        result = score_response(data, self.filters, self.match_score)
        result.evidence["model_armor_ms"] = round((time.perf_counter() - started) * 1000, 1)
        result.evidence["template"] = self.template_id
        self._remember(key, result)
        return result


def template_body(confidence: str = "MEDIUM_AND_ABOVE", malicious_uris: bool = True,
                  multi_language: bool = True) -> Dict[str, Any]:
    """A template with only the filters fAIrewall reads switched on.

    PII is left to fAIrewall's own redaction, and content-safety (RAI) filters
    are off: fAIrewall decides on actions, not on tone. ``confidence`` is the
    bar a text must reach to count as a match at all. When Model Armor reports
    the confidence it reached, HIGH blocks and lower levels flag; a match
    without a reported confidence blocks (see CONFIDENCE_SCORES).
    """
    if confidence not in ("LOW_AND_ABOVE", "MEDIUM_AND_ABOVE", "HIGH"):
        raise ValueError("confidence must be LOW_AND_ABOVE, MEDIUM_AND_ABOVE or HIGH")
    config: Dict[str, Any] = {
        "piAndJailbreakFilterSettings": {"filterEnforcement": "ENABLED", "confidenceLevel": confidence},
        "maliciousUriFilterSettings": {"filterEnforcement": "ENABLED" if malicious_uris else "DISABLED"},
    }
    body: Dict[str, Any] = {"filterConfig": config}
    if multi_language:
        body["templateMetadata"] = {"multiLanguageDetection": {"enableMultiLanguageDetection": True}}
    return body


def create_template(project: str, location: str, template_id: str, *,
                    confidence: str = "MEDIUM_AND_ABOVE", malicious_uris: bool = True,
                    token: Optional[str] = None, transport: Optional[Transport] = None,
                    timeout_s: float = 15.0) -> Dict[str, Any]:
    """Create a Model Armor template for fAIrewall. Needs roles/modelarmor.admin."""
    if not _TEMPLATE_ID.match(template_id):
        raise ValueError("Model Armor template IDs use up to 63 letters, digits, '_' or '-'")
    url = f"{endpoint(location)}/projects/{project}/locations/{location}/templates?templateId={template_id}"
    headers = {"Authorization": f"Bearer {TokenSource(token)()}",
               "Content-Type": "application/json"}
    body = json.dumps(template_body(confidence, malicious_uris)).encode("utf-8")
    return (transport or _http_post)(url, body, headers, timeout_s)
