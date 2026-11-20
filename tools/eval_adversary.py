"""Run many RANDOM attack sets against fAIrewall and report how many get through.

    python tools/eval_adversary.py [--seeds 12] [--count 3000]

Each seed generates a different attack set (fairewall.harness). Three engine
configurations are compared on the identical traffic:
    rules only        deterministic rules, no scoring detector
    + heuristic       rules + the hand-weighted HeuristicDetector
    + learned         rules + the LearnedDetector (trained on public data)

Reported per configuration, as mean +/- standard deviation across seeds:
    got through   attacks auto-approved (no block, no human)  <- lower is better
    benign hurt   benign actions that were NOT auto-approved but the authors
                  labeled as fine                              <- lower is better
Attacks are split by channel: "untrusted" (the platform labeled the content as
fetched, so the session is tainted) and "user" (not labeled; only text
inspection can notice), plus attacks that use no suspicious text at all.
"""

import argparse
import os
import random
import statistics as st
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from fairewall.detectors import HeuristicDetector, LearnedDetector  # noqa: E402
from fairewall.harness import demo_policy, generate_log  # noqa: E402
from fairewall.report import build_report  # noqa: E402


def ms(values):
    return "%5.1f%% +/- %.1f" % (st.mean(values), st.pstdev(values))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=12)
    ap.add_argument("--count", type=int, default=3000)
    ap.add_argument("--base", type=int, default=None, help="reproduce: starting seed")
    args = ap.parse_args()
    base = args.base if args.base is not None else random.SystemRandom().randrange(1, 10**6)
    seeds = [base + i for i in range(args.seeds)]
    print("seeds %d..%d, %d calls each (pass --base %d to reproduce)\n" % (seeds[0], seeds[-1], args.count, base))

    configs = {"rules only": [], "+ heuristic": [HeuristicDetector()], "+ learned": [LearnedDetector()]}
    results = {name: {"all": [], "untrusted": [], "user": [], "structure": [], "benign_hurt": [], "text_only": [], "p99": []}
               for name in configs}
    mut = {name: {} for name in configs}
    for seed in seeds:
        records = [r for r in generate_log(count=args.count, seed=seed) if "_meta" not in r]
        for name, dets in configs.items():
            rep = build_report(records, demo_policy(), 3, synthetic=True, detectors=dets)
            adv = rep["adversary"]
            r = results[name]
            r["all"].append(adv["got_through_pct"])
            for ch in ("untrusted", "user"):
                v = adv["by_channel"].get(ch)
                if v:
                    r[ch].append(100.0 * v["got_through"] / v["attacks"])
            v = adv["by_channel"].get("none")
            if v:
                r["structure"].append(100.0 * v["got_through"] / v["attacks"])
            al = rep["author_labels"]
            r["benign_hurt"].append(al["benign_stopped_pct"])
            r["text_only"].append(adv["stopped_only_by_text_inspection"])
            r["p99"].append(rep["latency_ms"]["p99"])
            for m, v in adv["by_mutation"].items():
                a, g = mut[name].get(m, (0, 0))
                mut[name][m] = (a + v["attacks"], g + v["got_through"])

    head = "%-14s %-17s %-17s %-17s %-17s %-17s" % ("config", "ALL attacks", "channel: untrusted", "channel: user",
                                                    "no-text structure", "benign hurt")
    print("Attacks that GOT THROUGH (lower is better)")
    print(head)
    for name, r in results.items():
        print("%-14s %-17s %-17s %-17s %-17s %-17s" % (name, ms(r["all"]), ms(r["untrusted"]), ms(r["user"]),
                                                       ms(r["structure"]), ms(r["benign_hurt"])))
    print("\nBy mutation, share that got through, pooled over all seeds")
    names = sorted({m for d in mut.values() for m in d})
    print("%-22s %s" % ("mutation", "  ".join("%-12s" % n for n in configs)))
    for m in names:
        cells = []
        for n in configs:
            a, g = mut[n].get(m, (0, 0))
            cells.append("%-12s" % ("%4.0f%% of %-4d" % (100.0 * g / a, a) if a else "-"))
        print("%-22s %s" % (m, "  ".join(cells)))
    print("\nLatency p99 per decision: " + ", ".join("%s %.2f ms" % (n, st.mean(r["p99"])) for n, r in results.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
