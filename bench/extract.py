"""Extract the shell commands autonomous coding agents actually ran.

Source: nebius/SWE-agent-trajectories — 6,670 real SWE-agent runs (Llama 8B/70B/405B)
attempting SWE-bench tasks. Each 'ai' turn ends with an action in a ``` fence. Most are
SWE-agent's own editor verbs (open/edit/goto/scroll/search_*); the rest are raw bash the
agent chose to run (python, pytest, rm, find, chmod, …). We keep the raw-bash commands.
"""
from __future__ import annotations
import re
import json
import sys
import pandas as pd

# SWE-agent's interface commands — not raw shell, handled by the harness.
AGENT_VERBS = {
    "open", "goto", "scroll_up", "scroll_down", "scroll", "create", "edit", "submit",
    "search_dir", "search_file", "find_file", "exit", "exit_context", "exit_cost",
    "exit_format", "skip", "edit_linting",
}

FENCE = re.compile(r"```(?:bash|sh|shell)?\s*\n?(.*?)```", re.S)


def actions(traj) -> list[str]:
    out = []
    for m in traj:
        if m.get("role") != "ai":
            continue
        txt = m.get("text") or ""
        blocks = FENCE.findall(txt)
        if not blocks:
            continue
        # SWE-agent takes the LAST fenced block as the action
        block = blocks[-1].strip()
        if block:
            out.append(block)
    return out


def first_token(cmd: str) -> str:
    cmd = cmd.strip()
    m = re.match(r"[A-Za-z0-9_./\-]+", cmd)
    return m.group(0) if m else ""


def is_raw_bash(cmd: str) -> bool:
    """True when the action is a shell command, not a SWE-agent editor verb."""
    tok = first_token(cmd)
    base = tok.rsplit("/", 1)[-1]
    if base in AGENT_VERBS:
        return False
    # multiline edit payloads: SWE-agent `edit` spans many lines ending with `end_of_edit`
    if "end_of_edit" in cmd:
        return False
    if not tok:
        return False
    return True


def main(parquet: str, out: str):
    df = pd.read_parquet(parquet)
    records = []
    for _, row in df.iterrows():
        inst = row["instance_id"]
        model = row["model_name"]
        solved = bool(row["target"])
        for cmd in actions(row["trajectory"]):
            if is_raw_bash(cmd):
                records.append({"instance_id": inst, "model": model, "solved": solved,
                                "command": cmd})
    with open(out, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"{len(records)} raw-bash commands from {len(df)} trajectories -> {out}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
