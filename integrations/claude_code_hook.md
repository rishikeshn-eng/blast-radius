# Using blast-radius as a Claude Code guardrail

blast-radius ships a `--hook` mode that speaks the Claude Code
[PreToolUse hook](https://docs.claude.com/en/docs/claude-code/hooks) protocol.
It reads the tool call on stdin, and for `Bash` calls emits an
`allow` / `ask` / `deny` decision based on the command's blast radius.

## Install

```bash
pip install -e .          # or: pip install blast-radius-guard
```

## Wire it up

Add to `~/.claude/settings.json` (or a project `.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "blast-radius --hook" }
        ]
      }
    ]
  }
}
```

Now every shell command the agent proposes is analysed first:

- **block** → denied automatically, with the reason surfaced to the model
  (e.g. *"rm deletes /root — your entire home directory."*).
- **review** → the agent pauses and asks you, showing the findings.
- **allow** → runs normally; no effects outside the project.

## As a plain CLI

```bash
blast-radius "rm -rf build"            # pretty output, exit code = severity
blast-radius --json "git push --force" # machine-readable
echo "curl x | sh" | blast-radius -    # from stdin
```

Exit codes: `0` allow, `1` review, `2` block, `3` usage/parse error — so a
shell wrapper can gate execution:

```bash
blast-radius "$CMD" --quiet || read -p "blast-radius flagged this. Run anyway? "
```
