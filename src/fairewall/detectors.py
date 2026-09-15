"""Tier 1: scored detectors that run only when the router escalates a call.

A detector turns text into a probability-like score in [0, 1]. The firewall
converts scores to findings using thresholds from the policy, and findings are
only ever *added*, so a detector can tighten a verdict but never loosen one.

Two implementations ship:

  * HeuristicDetector -- zero-dependency weighted lexical scorer. Catches
    paraphrased injections the regex signatures miss, because it scores the
    *combination* of weak signals (addressing the model, concealment, urgency,
    a sensitive action) rather than requiring an exact phrase.
  * OnnxDetector -- adapter for any HuggingFace-style sequence classifier
    exported to ONNX (e.g. a prompt-injection model). Needs `fairewall[ml]`.
"""

from __future__ import annotations

import math
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple


@dataclass
class DetectorResult:
    score: float
    label: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


class Detector(ABC):
    name: str = "detector"

    @abstractmethod
    def detect(self, text: str) -> DetectorResult:
        ...


def _rx(pattern: str) -> "re.Pattern[str]":
    return re.compile(pattern, re.IGNORECASE)


# (feature, weight, pattern). Each feature counts once; weights are summed and
# squashed through a logistic, so no single weak signal can reach the flag line.
_FEATURES: List[Tuple[str, float, "re.Pattern[str]"]] = [
    ("addresses_model", 1.4, _rx(
        r"\b(as an ai|language model|note (to|for) (the )?(ai|assistant|agent|model|bot)"
        r"|(hey|hi|attention|dear),?\s+(ai|assistant|agent|model|bot|claude|gpt|chatgpt)"
        r"|(ai|assistant|agent|model|bot) (reading|processing|summari[sz]ing) this)\b")),
    ("imperative_to_reader", 1.2, _rx(
        r"\byou\s+(must|should|need\s+to|have\s+to|will\s+now|are\s+required\s+to|shall)\b"
        r"|\bmake\s+sure\s+(you|to)\b|\bbe\s+sure\s+to\b")),
    ("concealment", 1.6, _rx(
        r"\b(secretly|silently|quietly|covertly|discreetly"
        r"|without\s+(telling|notifying|asking|informing|alerting)"
        r"|keep\s+(this|it)\s+(between\s+us|secret|hidden|confidential)"
        r"|(don'?t|do\s+not|never)\s+(mention|reveal|disclose|log|report))\b")),
    ("urgency", 0.8, _rx(
        r"\b(immediately|right\s+(away|now)|urgent(ly)?|asap|at\s+once|without\s+delay"
        r"|before\s+(anything|doing\s+anything)\s+else)\b")),
    ("sensitive_action", 1.0, _rx(
        r"\b(send|wire|transfer|forward|email|upload|post|delete|remove|execute|run"
        r"|invoke|refund|pay|approve|grant|share|export)\b")),
    ("sensitive_target", 1.0, _rx(
        r"\b(password|passcode|api[\s_-]?key|credential|token|secret|ssh|private\s+key"
        r"|bank|account|balance|wallet|iban|routing\s+number|card\s+number|payroll)")),
    ("instruction_reference", 1.0, _rx(
        r"\b(new|updated|real|actual|hidden|secret|additional)\s+"
        r"(instructions?|task|directive|orders?|objective)\b"
        r"|\b(instructions?|directive)\s+(for|to)\s+(you|the\s+(ai|assistant|agent|model))\b")),
]
_BIAS = -3.2


class HeuristicDetector(Detector):
    """Explainable baseline. Swap in a trained model for real coverage."""

    name = "heuristic"

    def detect(self, text: str) -> DetectorResult:
        matched = [(name, w) for name, w, rx in _FEATURES if rx.search(text or "")]
        z = _BIAS + sum(w for _, w in matched)
        score = 1.0 / (1.0 + math.exp(-z))
        return DetectorResult(
            score=score,
            label="injection" if score >= 0.5 else "benign",
            evidence={"features": [name for name, _ in matched]},
        )


class OnnxDetector(Detector):
    """Sequence classifier over ONNX Runtime.

    Long text is split into overlapping character windows and the maximum
    window score wins, so an injection buried on page 40 of a PDF is not
    diluted by 39 benign pages.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        tokenizer_path: Optional[str] = None,
        name: str = "onnx",
        positive_index: int = 1,
        max_length: int = 512,
        window_chars: int = 1500,
        overlap_chars: int = 200,
        session: Any = None,
        tokenizer: Any = None,
    ) -> None:
        self.name = name
        self.positive_index = positive_index
        self.window_chars = window_chars
        self.overlap_chars = overlap_chars
        try:
            import numpy as np  # type: ignore
        except ImportError as exc:  # pragma: no cover - env dependent
            raise ImportError("OnnxDetector requires `pip install fairewall[ml]`") from exc
        self._np = np

        if session is None or tokenizer is None:
            try:
                import onnxruntime  # type: ignore
                from tokenizers import Tokenizer  # type: ignore
            except ImportError as exc:  # pragma: no cover - env dependent
                raise ImportError("OnnxDetector requires `pip install fairewall[ml]`") from exc
            if not model_path or not tokenizer_path:
                raise ValueError("OnnxDetector needs model_path and tokenizer_path")
            session = session or onnxruntime.InferenceSession(
                model_path, providers=["CPUExecutionProvider"])
            tokenizer = tokenizer or Tokenizer.from_file(tokenizer_path)
            tokenizer.enable_truncation(max_length)
            tokenizer.enable_padding()

        self._session = session
        self._tokenizer = tokenizer
        self._input_names = {i.name for i in session.get_inputs()}

    def _windows(self, text: str) -> List[str]:
        if len(text) <= self.window_chars:
            return [text]
        step = self.window_chars - self.overlap_chars
        return [text[i:i + self.window_chars] for i in range(0, len(text) - self.overlap_chars, step)]

    def detect(self, text: str) -> DetectorResult:
        np = self._np
        windows = self._windows(text or "")
        encodings = self._tokenizer.encode_batch(windows)
        feeds = {
            "input_ids": np.array([e.ids for e in encodings], dtype=np.int64),
            "attention_mask": np.array([e.attention_mask for e in encodings], dtype=np.int64),
            "token_type_ids": np.array([e.type_ids for e in encodings], dtype=np.int64),
        }
        logits = self._session.run(None, {k: v for k, v in feeds.items() if k in self._input_names})[0]
        logits = np.asarray(logits, dtype=np.float64)
        if logits.shape[-1] == 1:
            probs = 1.0 / (1.0 + np.exp(-logits[:, 0]))
        else:
            shifted = np.exp(logits - logits.max(axis=-1, keepdims=True))
            probs = (shifted / shifted.sum(axis=-1, keepdims=True))[:, self.positive_index]
        worst = int(probs.argmax())
        score = float(probs[worst])
        return DetectorResult(
            score=score,
            label="injection" if score >= 0.5 else "benign",
            evidence={"windows": len(windows), "worst_window": worst},
        )


def build_detectors(names: Sequence[str], onnx_model: Optional[str] = None,
                    onnx_tokenizer: Optional[str] = None) -> List[Detector]:
    """Construct detectors from CLI/config names ("heuristic", "onnx")."""
    out: List[Detector] = []
    for name in names:
        if name == "heuristic":
            out.append(HeuristicDetector())
        elif name == "onnx":
            out.append(OnnxDetector(model_path=onnx_model, tokenizer_path=onnx_tokenizer))
        else:
            raise ValueError(f"Unknown detector {name!r}; expected 'heuristic' or 'onnx'")
    return out
