"""Measure the HeuristicDetector against independent data, and learn its weights.

    python tools/train_detector.py

What it does
  1. Scores the CURRENT hand-picked weights on deepset/prompt-injections.
  2. Learns new weights for the same seven features with logistic regression,
     fitted on the train split only.
  3. Compares both on the untouched test split, plus 5-fold cross-validation
     over train+test, so one lucky split cannot flatter the result.
  4. Prints a ready-to-paste weights block. It never edits detectors.py.

The seven features were written for agent-hijacking text ("send the bank
details secretly"). deepset is mostly chatbot-style injections ("ignore the
above and say X"), a different distribution, so low recall is expected and is
itself the finding: it says how far the features generalize.
"""

from __future__ import annotations

import math
import os
import sys
from typing import List, Tuple

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "src"))

import detector_data  # noqa: E402
from fairewall import detectors  # noqa: E402

FEATURES = detectors._FEATURES
NAMES = [n for n, _, _ in FEATURES]
HAND_W = np.array([w for _, w, _ in FEATURES])
HAND_BIAS = detectors._BIAS
FLAG, BLOCK = 0.5, 0.85  # the policy's default thresholds


def matrix(rows: List[dict]) -> Tuple[np.ndarray, np.ndarray]:
    x = np.array([[1.0 if rx.search(r["text"]) else 0.0 for _, _, rx in FEATURES] for r in rows])
    y = np.array([r["label"] for r in rows])
    return x, y


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-z))


def metrics(y, score, thr=FLAG) -> dict:
    pred = score >= thr
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec == prec and prec + rec else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=prec, recall=rec, f1=f1,
                fpr=fp / (fp + tn) if fp + tn else 0.0,
                auc=roc_auc_score(y, score) if len(set(y)) > 1 else float("nan"))


def show(title: str, m: dict) -> None:
    print("  %-34s precision %.2f  recall %.2f  F1 %.2f  false-alarm %.1f%%  AUC %.2f   (TP %d FP %d FN %d TN %d)"
          % (title, m["precision"], m["recall"], m["f1"], 100 * m["fpr"], m["auc"],
             m["tp"], m["fp"], m["fn"], m["tn"]))


def fit(x, y, c=1.0) -> Tuple[np.ndarray, float]:
    clf = LogisticRegression(C=c, class_weight="balanced", max_iter=2000)
    clf.fit(x, y)
    return clf.coef_[0], float(clf.intercept_[0])


def main() -> int:
    data = detector_data.deepset()
    train, test = data["train"], data["test"]
    xtr, ytr = matrix(train)
    xte, yte = matrix(test)
    eng_te = np.array([detector_data.looks_english(r["text"]) for r in test])

    print("Data: deepset/prompt-injections  train=%d (%d injection)  test=%d (%d injection)"
          % (len(ytr), ytr.sum(), len(yte), yte.sum()))
    print("Base rate if you flagged nothing: recall 0.00. If you flagged everything: precision %.2f"
          % (yte.mean()))

    print("\nCoverage: how often each feature fires")
    for i, n in enumerate(NAMES):
        print("  %-22s injections %5.1f%%   benign %5.1f%%"
              % (n, 100 * xtr[ytr == 1, i].mean(), 100 * xtr[ytr == 0, i].mean()))
    print("  any feature fires      injections %5.1f%%   benign %5.1f%%"
          % (100 * (xtr[ytr == 1].sum(1) > 0).mean(), 100 * (xtr[ytr == 0].sum(1) > 0).mean()))

    hand_te = sigmoid(HAND_BIAS + xte @ HAND_W)
    print("\n1) CURRENT hand-picked weights, held-out test split")
    show("all test rows (flag >= 0.5)", metrics(yte, hand_te))
    show("English-looking rows only", metrics(yte[eng_te], hand_te[eng_te]))
    show("block threshold (>= 0.85)", metrics(yte, hand_te, BLOCK))

    w, b = fit(xtr, ytr)
    learn_te = sigmoid(b + xte @ w)
    print("\n2) LEARNED weights (fitted on train only), same held-out test split")
    show("all test rows (flag >= 0.5)", metrics(yte, learn_te))
    show("English-looking rows only", metrics(yte[eng_te], learn_te[eng_te]))
    show("block threshold (>= 0.85)", metrics(yte, learn_te, BLOCK))

    # 5-fold CV over everything, repeated, fitting only inside each fold.
    xall, yall = np.vstack([xtr, xte]), np.concatenate([ytr, yte])
    aucs_h, aucs_l, f1_h, f1_l = [], [], [], []
    for seed in range(5):
        for tr, te in StratifiedKFold(5, shuffle=True, random_state=seed).split(xall, yall):
            wf, bf = fit(xall[tr], yall[tr])
            sh = sigmoid(HAND_BIAS + xall[te] @ HAND_W)
            sl = sigmoid(bf + xall[te] @ wf)
            aucs_h.append(roc_auc_score(yall[te], sh)); aucs_l.append(roc_auc_score(yall[te], sl))
            f1_h.append(metrics(yall[te], sh)["f1"]); f1_l.append(metrics(yall[te], sl)["f1"])
    print("\n3) 5x5-fold cross-validation over train+test (%d rows)" % len(yall))
    print("  hand-picked: AUC %.3f +/- %.3f   F1 %.3f +/- %.3f" % (np.mean(aucs_h), np.std(aucs_h), np.mean(f1_h), np.std(f1_h)))
    print("  learned:     AUC %.3f +/- %.3f   F1 %.3f +/- %.3f" % (np.mean(aucs_l), np.std(aucs_l), np.mean(f1_l), np.std(f1_l)))

    wall, ball = fit(xall, yall)
    print("\nWeights (hand-picked -> learned on train -> learned on all rows)")
    for n, h, a, c in zip(NAMES, HAND_W, w, wall):
        print("  %-22s %5.2f   %6.2f   %6.2f" % (n, h, a, c))
    print("  %-22s %5.2f   %6.2f   %6.2f" % ("bias", HAND_BIAS, b, ball))

    # Reference ceiling: what a plain bag-of-words model can learn from the same data.
    from sklearn.feature_extraction.text import TfidfVectorizer
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)
    xb = vec.fit_transform([r["text"] for r in train])
    clf = LogisticRegression(C=4.0, class_weight="balanced", max_iter=3000).fit(xb, ytr)
    sb = clf.predict_proba(vec.transform([r["text"] for r in test]))[:, 1]
    print("\nReference only: bag-of-words logistic regression (not used by fAIrewall)")
    show("all test rows (flag >= 0.5)", metrics(yte, sb))
    show("English-looking rows only", metrics(yte[eng_te], sb[eng_te]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
