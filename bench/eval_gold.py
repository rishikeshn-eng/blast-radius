"""Evaluate blast-radius against the hand-labelled gold set.

Treats the three verdicts as an ordinal scale (allow<review<block) and reports:
  * exact-match accuracy
  * confusion matrix
  * per-tier precision/recall/F1 for the 'block' and 'flag' (review-or-block) decisions
  * the operationally important errors: under-calls (predicted softer than gold) on
    dangerous commands, and over-calls (predicted harsher) on safe commands.
"""
from __future__ import annotations
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from blast_radius.analyze import analyze  # noqa: E402
from gold import GOLD  # noqa: E402

RANK = {"allow": 0, "review": 1, "block": 2}
LABELS = ["allow", "review", "block"]


def prf(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 1.0
    r = tp / (tp + fn) if (tp + fn) else 1.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return round(p, 3), round(r, 3), round(f, 3)


def main():
    confusion = {g: {p: 0 for p in LABELS} for g in LABELS}
    exact = 0
    undercalls, overcalls = [], []
    rows = []
    for gold, cmd in GOLD:
        r = analyze(cmd, project_root="/repo", home="/root")
        pred = r.verdict
        confusion[gold][pred] += 1
        if pred == gold:
            exact += 1
        elif RANK[pred] < RANK[gold]:
            undercalls.append((gold, pred, cmd, [f.message for f in r.top_findings()[:1]]))
        else:
            overcalls.append((gold, pred, cmd, [f.message for f in r.top_findings()[:1]]))
        rows.append({"gold": gold, "pred": pred, "command": cmd,
                     "why": [f.message for f in r.top_findings()[:2]]})

    n = len(GOLD)
    # block detection
    b_tp = confusion["block"]["block"]
    b_fp = confusion["allow"]["block"] + confusion["review"]["block"]
    b_fn = confusion["block"]["allow"] + confusion["block"]["review"]
    # "flag" = review or block (i.e. do NOT silently allow); positive class = gold!=allow
    flag_tp = sum(confusion[g][p] for g in ("review", "block") for p in ("review", "block"))
    flag_fp = sum(confusion["allow"][p] for p in ("review", "block"))
    flag_fn = sum(confusion[g]["allow"] for g in ("review", "block"))

    out = {
        "n": n,
        "exact_accuracy": round(exact / n, 3),
        "confusion": confusion,
        "block": dict(zip(("precision", "recall", "f1"), prf(b_tp, b_fp, b_fn))),
        "flag_vs_allow": dict(zip(("precision", "recall", "f1"), prf(flag_tp, flag_fp, flag_fn))),
        "dangerous_undercalls": undercalls,     # missed danger — the costly error
        "safe_overcalls": overcalls,            # nagging on safe commands
        "n_undercall": len(undercalls),
        "n_overcall": len(overcalls),
    }
    os.makedirs("bench/out", exist_ok=True)
    with open("bench/out/gold_eval.json", "w") as f:
        json.dump({**out, "rows": rows}, f, indent=2)

    print(f"gold cases: {n}")
    print(f"exact-match accuracy: {out['exact_accuracy']}")
    print(f"block  precision/recall/F1: {out['block']}")
    print(f"flag   precision/recall/F1: {out['flag_vs_allow']}")
    print("confusion (rows=gold, cols=pred):")
    print("            " + "".join(f"{p:>8}" for p in LABELS))
    for g in LABELS:
        print(f"    {g:>7} " + "".join(f"{confusion[g][p]:>8}" for p in LABELS))
    if undercalls:
        print(f"\nDANGEROUS UNDER-CALLS ({len(undercalls)}):")
        for g, pr, cmd, why in undercalls:
            print(f"   gold={g} pred={pr}: {cmd[:60]}  {why}")
    if overcalls:
        print(f"\nSAFE OVER-CALLS ({len(overcalls)}):")
        for g, pr, cmd, why in overcalls:
            print(f"   gold={g} pred={pr}: {cmd[:60]}  {why}")


if __name__ == "__main__":
    main()
