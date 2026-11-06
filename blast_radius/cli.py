"""Command-line interface for blast-radius.

Usage:
    blast-radius "rm -rf build"              analyse one command (pretty output)
    blast-radius --json "git push --force"   machine-readable JSON
    echo "cmd" | blast-radius -              read command from stdin
    blast-radius --hook                      Claude Code PreToolUse hook mode (reads JSON on stdin)

Exit status: 0 allow, 1 review, 2 block, 3 usage/parse error. This lets a wrapper
gate execution: ``blast-radius "$CMD" || confirm_with_user``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .analyze import analyze, ALLOW, REVIEW, BLOCK

_EXIT = {ALLOW: 0, REVIEW: 1, BLOCK: 2}
_COLORS = {ALLOW: "\033[32m", REVIEW: "\033[33m", BLOCK: "\033[31m"}
_ICON = {ALLOW: "✓", REVIEW: "⚠", BLOCK: "✗"}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _pretty(report, color: bool) -> str:
    def c(code):
        return code if color else ""
    v = report.verdict
    lines = []
    head = f"{c(_COLORS[v])}{c(_BOLD)}{_ICON[v]} {v.upper()}{c(_RESET)}"
    lines.append(f"{head}  {c(_DIM)}{report.command.strip()[:100]}{c(_RESET)}")
    if report.programs:
        lines.append(f"  {c(_DIM)}programs:{c(_RESET)} {', '.join(sorted(set(report.programs)))}")
    if not report.findings:
        lines.append(f"  {c(_DIM)}no effects outside the project to flag{c(_RESET)}")
    for f in report.top_findings():
        col = c(_COLORS[f.severity])
        lines.append(f"  {col}{_ICON[f.severity]}{c(_RESET)} {f.message}")
    if report.dynamic:
        lines.append(f"  {c(_DIM)}note: parts of this command are decided at runtime and can't be fully checked.{c(_RESET)}")
    return "\n".join(lines)


def _run_hook() -> int:
    """Claude Code PreToolUse hook: read the tool call on stdin, gate Bash calls.

    Emits a hook JSON decision. 'block' -> deny, 'review' -> ask, 'allow' -> approve.
    See https://docs.claude.com/en/docs/claude-code/hooks for the contract.
    """
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(json.dumps({"continue": True}))
        return 0
    tool = payload.get("tool_name") or payload.get("tool")
    tin = payload.get("tool_input") or payload.get("input") or {}
    command = tin.get("command")
    if tool not in ("Bash", "bash") or not command:
        print(json.dumps({"continue": True}))
        return 0
    cwd = payload.get("cwd") or os.getcwd()
    report = analyze(command, project_root=cwd)
    reasons = "; ".join(f.message for f in report.top_findings()[:3])
    if report.verdict == BLOCK:
        decision = {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": f"blast-radius blocked this command: {reasons}"}}
    elif report.verdict == REVIEW:
        decision = {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "ask",
            "permissionDecisionReason": f"blast-radius flagged this for review: {reasons}"}}
    else:
        decision = {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "allow",
            "permissionDecisionReason": "blast-radius: no effects outside the project"}}
    print(json.dumps(decision))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="blast-radius",
                                description="Static blast-radius analysis for shell commands.")
    p.add_argument("command", nargs="?", help="the command to analyse ('-' reads stdin)")
    p.add_argument("--json", action="store_true", help="output machine-readable JSON")
    p.add_argument("--hook", action="store_true", help="Claude Code PreToolUse hook mode")
    p.add_argument("--project", "-C", default=None, help="project root (default: cwd)")
    p.add_argument("--quiet", "-q", action="store_true", help="print nothing; use exit status only")
    args = p.parse_args(argv)

    if args.hook:
        return _run_hook()

    if args.command == "-" or (args.command is None and not sys.stdin.isatty()):
        command = sys.stdin.read()
    elif args.command is None:
        p.print_help()
        return 3
    else:
        command = args.command

    report = analyze(command, project_root=args.project or os.getcwd())

    if args.json:
        print(json.dumps(report.to_json(), indent=2))
    elif not args.quiet:
        print(_pretty(report, _supports_color()))
    return _EXIT.get(report.verdict, 3)


if __name__ == "__main__":
    sys.exit(main())
