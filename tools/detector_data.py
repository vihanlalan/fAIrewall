"""Fetch public, independently labeled prompt-injection data for scorer evaluation.

Why this exists: scoring the detector on attacks its own authors wrote proves
nothing. These datasets were labeled by other people. Rows are cached under
tools/_cache/ (git-ignored); nothing from this repo is sent anywhere, the only
network traffic is read-only requests to Hugging Face's public dataset API.

    deepset/prompt-injections   546 train + 116 test, label 1 = injection,
                                English and German.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Dict, List

CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_cache")
API = "https://datasets-server.huggingface.co/rows"


def _get(url: str, tries: int = 8) -> dict:
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                return json.load(resp)
        except (urllib.error.URLError, TimeoutError):
            if attempt == tries - 1:
                raise
            time.sleep(min(30.0, 2.0 * 2 ** attempt))
    raise RuntimeError("unreachable")


def fetch(dataset: str, split: str, text_col: str = "text", label_col: str = "label",
          positive: str = "1") -> List[Dict]:
    """Return rows of {text, label} for one split, using the local cache if present."""
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, "%s__%s.json" % (dataset.replace("/", "_"), split))
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    rows: List[Dict] = []
    offset, page = 0, 100
    while True:
        data = _get("%s?dataset=%s&config=default&split=%s&offset=%d&length=%d"
                    % (API, dataset, split, offset, page))
        batch = [r["row"] for r in data.get("rows", [])]
        rows.extend({"text": b[text_col], "label": int(str(b[label_col]) == positive)} for b in batch)
        offset += page
        time.sleep(0.7)  # stay well under the public API's rate limit
        if offset >= data.get("num_rows_total", 0) or not batch:
            break
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rows, fh)
    return rows


def deepset() -> Dict[str, List[Dict]]:
    return {s: fetch("deepset/prompt-injections", s) for s in ("train", "test")}


def xtram1() -> Dict[str, List[Dict]]:
    """xTRam1/safe-guard-prompt-injection: ~10k rows, LLM-generated injections vs benign."""
    return {s: fetch("xTRam1/safe-guard-prompt-injection", s) for s in ("train", "test")}


def jackhhao() -> Dict[str, List[Dict]]:
    """jackhhao/jailbreak-classification: jailbreak prompts (label 1) vs benign prompts."""
    return {s: fetch("jackhhao/jailbreak-classification", s, "prompt", "type", "jailbreak")
            for s in ("train", "test")}


def looks_english(text: str) -> bool:
    """Crude filter: the scorer is English-only, so report English rows separately."""
    german = (" der ", " die ", " das ", " und ", " nicht ", " ich ", " ist ", " zu ",
              " ein ", " sie ", " mit ", " für ", " wie ", " was ", " auf ", " bitte")
    low = " " + text.lower() + " "
    return sum(g in low for g in german) < 2 and all(ord(c) < 0x250 for c in text)


if __name__ == "__main__":
    for name, loader in (("deepset", deepset), ("xtram1", xtram1), ("jackhhao", jackhhao)):
        for split, rows in loader().items():
            pos = sum(r["label"] for r in rows)
            print("%-9s %-5s rows=%d attack=%d benign=%d" % (name, split, len(rows), pos, len(rows) - pos))
