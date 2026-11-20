"""Train the LearnedDetector (bag-of-words logistic regression) and export it as JSON.

    python tools/train_learned_detector.py            # evaluate only
    python tools/train_learned_detector.py --export   # also write the model file

Honest evaluation rule: the number to trust is leave-one-dataset-out. The model
is trained on two datasets and scored on the third, which it never saw, so it
cannot memorise that dataset's quirks. In-distribution scores are printed too
but are optimistic.

The exported model is dependency-free at run time: fairewall.detectors reads the
JSON and does the arithmetic in plain Python (no numpy, no sklearn).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from typing import Dict, List

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "src"))

import detector_data  # noqa: E402

MODEL_PATH = os.path.join(HERE, "..", "src", "fairewall", "models", "injection_lr.json")
VEC = dict(lowercase=True, ngram_range=(1, 2), min_df=3, max_features=12000, sublinear_tf=True)
C_REG = 2.0


def train(rows: List[dict]):
    vec = TfidfVectorizer(**VEC)
    x = vec.fit_transform([r["text"] for r in rows])
    clf = LogisticRegression(C=C_REG, class_weight="balanced", max_iter=4000)
    clf.fit(x, [r["label"] for r in rows])
    return vec, clf


def score(vec, clf, rows: List[dict]) -> np.ndarray:
    return clf.predict_proba(vec.transform([r["text"] for r in rows]))[:, 1]


def report(title: str, y: np.ndarray, s: np.ndarray) -> None:
    out = []
    for thr in (0.5, 0.85):
        pred = s >= thr
        tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
        prec = tp / (tp + fp) if tp + fp else float("nan")
        rec = tp / (tp + fn) if tp + fn else 0.0
        out.append("@%.2f recall %.2f precision %.2f false-alarm %.1f%%"
                   % (thr, rec, prec, 100 * fp / max(1, fp + tn)))
    print("  %-26s n=%-5d AUC %.3f   %s" % (title, len(y), roc_auc_score(y, s), "   ".join(out)))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--export", action="store_true")
    args = ap.parse_args()

    sets: Dict[str, Dict[str, List[dict]]] = {
        "deepset": detector_data.deepset(),
        "xtram1": detector_data.xtram1(),
        "jackhhao": detector_data.jackhhao(),
    }
    allrows = {k: v["train"] + v["test"] for k, v in sets.items()}

    print("Leave-one-dataset-out (train on the other two, test on the unseen one)")
    for held in sets:
        tr = [r for k, rows in allrows.items() if k != held for r in rows]
        vec, clf = train(tr)
        y = np.array([r["label"] for r in allrows[held]])
        report("unseen: " + held, y, score(vec, clf, allrows[held]))

    print("\nIn-distribution (train on all train splits, test on all test splits) - optimistic")
    tr = [r for v in sets.values() for r in v["train"]]
    te = [r for v in sets.values() for r in v["test"]]
    vec, clf = train(tr)
    report("pooled test split", np.array([r["label"] for r in te]), score(vec, clf, te))

    if args.export:
        rows = [r for rs in allrows.values() for r in rs]
        vec, clf = train(rows)
        terms = vec.get_feature_names_out()
        model = {
            "kind": "bow-logistic-regression",
            "trained": datetime.date.today().isoformat(),
            "trained_on": {k: len(v) for k, v in allrows.items()},
            "vectorizer": {"ngram_range": [1, 2], "sublinear_tf": True, "token_pattern": r"(?u)\b\w\w+\b"},
            "bias": float(clf.intercept_[0]),
            "terms": [[str(t), round(float(i), 6), round(float(c), 6)]
                      for t, i, c in zip(terms, vec.idf_, clf.coef_[0])],
            "note": "Trained on public chat-style injection/jailbreak data. Not trained on "
                    "agent tool-call text; measure on your own traffic before relying on it.",
        }
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, "w", encoding="utf-8") as fh:
            json.dump(model, fh, separators=(",", ":"))
        print("\nWrote %s (%d terms, %.0f KB)" % (os.path.normpath(MODEL_PATH), len(terms),
                                                os.path.getsize(MODEL_PATH) / 1024))
    return 0


if __name__ == "__main__":
    sys.exit(main())
