"""Run blast-radius over a corpus of commands and summarise results.

Reports: verdict distribution, parser success rate, latency, the finding codes that
fired, and a sample of the highest-severity commands (written to a file, not stdout).
"""
from __future__ import annotations
import json
import sys
import time
import collections
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from blast_radius.analyze import analyze  # noqa: E402

PROJECT = "/repo"
HOME = "/root"


def load(path: str):
    if path.endswith(".jsonl"):
        for line in open(path):
            yield json.loads(line)
    else:  # plain commands, one per line (nl2bash .cm)
        for line in open(path, errors="replace"):
            line = line.rstrip("\n")
            if line.strip():
                yield {"command": line}


def main(path: str, label: str, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    verdicts = collections.Counter()
    codes = collections.Counter()
    parse_fail = 0
    dynamic = 0
    total = 0
    latencies = []
    blocks = []
    reviews_sample = []
    by_solved = {True: collections.Counter(), False: collections.Counter()}

    for rec in load(path):
        cmd = rec["command"]
        if len(cmd) > 20000:
            continue
        total += 1
        t0 = time.perf_counter()
        try:
            r = analyze(cmd, project_root=PROJECT, home=HOME)
        except Exception as e:  # analyser must never crash; record if it does
            verdicts["crash"] += 1
            blocks.append({"command": cmd[:500], "verdict": "CRASH", "error": repr(e)})
            continue
        latencies.append((time.perf_counter() - t0) * 1000)
        verdicts[r.verdict] += 1
        if not r.parse_ok:
            parse_fail += 1
        if r.dynamic:
            dynamic += 1
        for f in r.findings:
            codes[f.code] += 1
        if "solved" in rec:
            by_solved[rec["solved"]][r.verdict] += 1
        if r.verdict == "block":
            blocks.append({"command": cmd[:500], "verdict": r.verdict,
                           "why": [f.message for f in r.top_findings()[:2]],
                           **({"instance": rec.get("instance_id"), "model": rec.get("model"),
                               "solved": rec.get("solved")} if "instance_id" in rec else {})})
        elif r.verdict == "review" and len(reviews_sample) < 400:
            reviews_sample.append({"command": cmd[:300],
                                   "why": r.top_findings()[0].message if r.findings else ""})

    latencies.sort()
    n = len(latencies)
    summary = {
        "label": label, "total": total,
        "verdicts": dict(verdicts),
        "verdict_pct": {k: round(100 * v / total, 2) for k, v in verdicts.items()},
        "parse_fail": parse_fail, "parse_fail_pct": round(100 * parse_fail / total, 3),
        "dynamic": dynamic, "dynamic_pct": round(100 * dynamic / total, 2),
        "latency_ms": {
            "mean": round(sum(latencies) / n, 4) if n else 0,
            "p50": round(latencies[n // 2], 4) if n else 0,
            "p95": round(latencies[int(n * 0.95)], 4) if n else 0,
            "p99": round(latencies[int(n * 0.99)], 4) if n else 0,
            "max": round(latencies[-1], 4) if n else 0,
        },
        "top_codes": codes.most_common(25),
        "n_block": verdicts["block"], "n_review": verdicts["review"],
    }
    if any(by_solved.values()):
        summary["by_solved"] = {str(k): dict(v) for k, v in by_solved.items()}

    with open(os.path.join(out_dir, f"{label}_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    with open(os.path.join(out_dir, f"{label}_blocks.json"), "w") as f:
        json.dump(blocks, f, indent=2)
    with open(os.path.join(out_dir, f"{label}_reviews.json"), "w") as f:
        json.dump(reviews_sample, f, indent=2)

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3])
