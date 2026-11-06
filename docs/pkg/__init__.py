"""blast-radius — static blast-radius analysis for shell commands an AI agent runs.

Public API:
    from blast_radius import analyze
    report = analyze("rm -rf build", project_root="/my/project")
    report.verdict        # "allow" | "review" | "block"
    report.findings       # ranked list of human-readable reasons
    report.to_json()      # full structured result
"""
from .analyze import analyze, Report, Effect, Finding, ALLOW, REVIEW, BLOCK  # noqa: F401
from .shell import parse, ParseError  # noqa: F401

__version__ = "0.1.0"
__all__ = ["analyze", "Report", "Effect", "Finding", "parse", "ParseError",
           "ALLOW", "REVIEW", "BLOCK"]
