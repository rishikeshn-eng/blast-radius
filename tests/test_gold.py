"""Regression test: blast-radius must never MISS a dangerous command on the gold set."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bench"))
from gold import GOLD
from blast_radius import analyze

RANK = {"allow": 0, "review": 1, "block": 2}


def test_no_dangerous_undercalls():
    """No gold command may be rated SOFTER than its label (the safety-critical property)."""
    bad = []
    for label, cmd in GOLD:
        pred = analyze(cmd, project_root="/repo", home="/root").verdict
        if RANK[pred] < RANK[label]:
            bad.append((label, pred, cmd))
    assert not bad, f"under-called dangerous commands: {bad}"


def test_block_recall_is_total():
    gold_blocks = [c for l, c in GOLD if l == "block"]
    missed = [c for c in gold_blocks
              if analyze(c, project_root="/repo", home="/root").verdict != "block"]
    assert not missed, f"missed blocks: {missed}"


def test_exact_accuracy_threshold():
    ok = sum(1 for l, c in GOLD
             if analyze(c, project_root="/repo", home="/root").verdict == l)
    assert ok / len(GOLD) >= 0.90
