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

import json
import math
import os
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
    """Explainable baseline. Swap in a trained model for real coverage.

    Measured (tools/train_detector.py): on independent public data
    (deepset/prompt-injections test split) this scorer caught 0 of 60 attacks,
    AUC 0.53. Its seven features were written for agent-hijack wording and
    almost never fire on other attack styles; re-fitting the weights does not
    fix that. Treat it as a demo of the mechanism, not as a detector. Use
    LearnedDetector for real signal.
    """

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


_TOKEN = re.compile(r"(?u)\b\w\w+\b")
_DEFAULT_MODEL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "injection_lr.json")


class LearnedDetector(Detector):
    """Bag-of-words logistic regression trained on public injection datasets.

    Pure Python at run time: it reads a JSON file of (term, idf, weight) rows and
    does the arithmetic itself, so it adds no dependency. The arithmetic mirrors
    scikit-learn's TfidfVectorizer + LogisticRegression (a parity test checks it).

    Measured honestly (tools/train_learned_detector.py, leave-one-dataset-out,
    i.e. scored on a dataset it never saw during training):
        jackhhao jailbreaks   AUC 0.98   recall 0.97 @0.5   false alarms 15%
        xTRam1 injections     AUC 0.94   recall 0.74 @0.5   false alarms 5.6%
        deepset (multilingual, human-written)  AUC 0.75  recall 0.14 @0.5
    It was trained on chat-style attacks, not on agent tool-call text, and it
    reads English words only: paraphrase, typos, other languages and encodings
    can still slip past. It only ever tightens a verdict.
    """

    name = "learned"

    def __init__(self, model_path: Optional[str] = None) -> None:
        path = model_path or _DEFAULT_MODEL
        with open(path, "r", encoding="utf-8") as fh:
            model = json.load(fh)
        self.bias: float = float(model["bias"])
        self.idf: Dict[str, float] = {t: float(i) for t, i, _ in model["terms"]}
        self.weight: Dict[str, float] = {t: float(c) for t, _, c in model["terms"]}
        self.info: Dict[str, Any] = {k: model[k] for k in ("trained", "trained_on", "note") if k in model}

    @staticmethod
    def _terms(text: str) -> List[str]:
        tokens = _TOKEN.findall((text or "").lower())
        return tokens + [tokens[i] + " " + tokens[i + 1] for i in range(len(tokens) - 1)]

    def detect(self, text: str) -> DetectorResult:
        counts: Dict[str, int] = {}
        for term in self._terms(text):
            if term in self.idf:
                counts[term] = counts.get(term, 0) + 1
        values = {t: (1.0 + math.log(n)) * self.idf[t] for t, n in counts.items()}
        norm = math.sqrt(sum(v * v for v in values.values()))
        z = self.bias
        top: List[Tuple[float, str]] = []
        if norm > 0:
            for t, v in values.items():
                contribution = self.weight[t] * v / norm
                z += contribution
                top.append((contribution, t))
        score = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
        top.sort(reverse=True)
        return DetectorResult(
            score=score,
            label="injection" if score >= 0.5 else "benign",
            evidence={"top_terms": [t for c, t in top[:5] if c > 0]},
        )


def build_detectors(names: Sequence[str], onnx_model: Optional[str] = None,
                    onnx_tokenizer: Optional[str] = None) -> List[Detector]:
    """Construct detectors from CLI/config names ("heuristic", "learned", "onnx")."""
    out: List[Detector] = []
    for name in names:
        if name == "heuristic":
            out.append(HeuristicDetector())
        elif name == "learned":
            out.append(LearnedDetector())
        elif name == "onnx":
            out.append(OnnxDetector(model_path=onnx_model, tokenizer_path=onnx_tokenizer))
        else:
            raise ValueError(f"Unknown detector {name!r}; expected 'heuristic', 'learned' or 'onnx'")
    return out
