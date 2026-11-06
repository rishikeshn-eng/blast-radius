"""Static blast-radius analysis for a shell command an AI agent is about to run.

Given a command line and a project root, :func:`analyze` returns a structured
report: the programs it will run, the effects each has, the paths those effects
land on, and an overall verdict (allow / review / block) with human-readable
reasons. It never executes anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

from . import paths, tools
from .shell import (
    parse, ParseError, Script, SimpleCommand, Compound, Word,
)

# --------------------------------------------------------------------------- #
# report model
# --------------------------------------------------------------------------- #

# severity bands
ALLOW, REVIEW, BLOCK = "allow", "review", "block"
_SEV_ORDER = {ALLOW: 0, REVIEW: 1, BLOCK: 2}


@dataclass
class Effect:
    verb: str                      # read/write/delete/...
    target: Optional[paths.Target]
    program: str                   # the tool producing it
    recursive: bool = False
    forced: bool = False
    note: str = ""

    def to_json(self) -> dict:
        t = self.target
        return {
            "verb": self.verb, "program": self.program, "recursive": self.recursive,
            "forced": self.forced, "note": self.note,
            "target": None if t is None else {
                "shown": t.shown, "scope": t.scope, "broad": t.broad,
                "secret": t.secret, "autorun": t.autorun,
            },
        }


@dataclass
class Finding:
    code: str
    severity: str
    message: str
    effect: Optional[Effect] = None

    def to_json(self) -> dict:
        d = {"code": self.code, "severity": self.severity, "message": self.message}
        if self.effect:
            d["effect"] = self.effect.to_json()
        return d


@dataclass
class Report:
    command: str
    verdict: str = ALLOW
    programs: list = field(default_factory=list)
    effects: list = field(default_factory=list)       # list[Effect]
    findings: list = field(default_factory=list)       # list[Finding]
    parse_ok: bool = True
    parse_error: str = ""
    dynamic: bool = False                              # could not fully resolve
    env: dict = field(default_factory=dict)

    def add(self, code: str, severity: str, message: str, effect: Optional[Effect] = None) -> None:
        self.findings.append(Finding(code, severity, message, effect))
        if _SEV_ORDER[severity] > _SEV_ORDER[self.verdict]:
            self.verdict = severity

    def top_findings(self) -> list:
        return sorted(self.findings, key=lambda f: -_SEV_ORDER[f.severity])

    def to_json(self) -> dict:
        return {
            "command": self.command, "verdict": self.verdict, "parse_ok": self.parse_ok,
            "parse_error": self.parse_error, "dynamic": self.dynamic,
            "programs": sorted(set(self.programs)),
            "effects": [e.to_json() for e in self.effects],
            "findings": [f.to_json() for f in self.top_findings()],
        }


# --------------------------------------------------------------------------- #
# severity rules — scope x verb matrix
# --------------------------------------------------------------------------- #

# Base severity for a (verb, scope) pair. Scopes come from paths.classify().
# Missing pairs default to ALLOW for reads, REVIEW for mutations.
_MUTATING = {"delete", "write", "overwrite_inplace", "move", "chmod", "chown", "create"}

_SEVERITY = {
    # deletes
    ("delete", "project"): REVIEW, ("delete", "project_root"): BLOCK,
    ("delete", "home"): BLOCK, ("delete", "home_root"): BLOCK,
    ("delete", "system"): BLOCK, ("delete", "root"): BLOCK, ("delete", "outside"): BLOCK,
    ("delete", "tmp"): ALLOW, ("delete", "null"): ALLOW, ("delete", "unknown"): REVIEW,
    ("delete", "device"): BLOCK,
    # in-place overwrite / write
    ("write", "project"): ALLOW, ("write", "home"): REVIEW, ("write", "home_root"): REVIEW,
    ("write", "system"): BLOCK, ("write", "root"): BLOCK, ("write", "outside"): REVIEW,
    ("write", "device"): BLOCK, ("write", "tmp"): ALLOW, ("write", "null"): ALLOW,
    ("overwrite_inplace", "project"): ALLOW, ("overwrite_inplace", "home"): REVIEW,
    ("overwrite_inplace", "system"): BLOCK, ("overwrite_inplace", "outside"): REVIEW,
    ("overwrite_inplace", "home_root"): REVIEW,
    # create
    ("create", "project"): ALLOW, ("create", "tmp"): ALLOW, ("create", "home"): ALLOW,
    ("create", "system"): REVIEW, ("create", "outside"): REVIEW, ("create", "null"): ALLOW,
    ("create", "root"): BLOCK,
    # move
    ("move", "project"): REVIEW, ("move", "home"): REVIEW, ("move", "system"): BLOCK,
    ("move", "outside"): REVIEW, ("move", "home_root"): BLOCK,
    # permissions
    ("chmod", "project"): ALLOW, ("chmod", "home"): REVIEW, ("chmod", "system"): BLOCK,
    ("chmod", "home_root"): REVIEW, ("chmod", "outside"): REVIEW, ("chmod", "root"): BLOCK,
    ("chown", "project"): REVIEW, ("chown", "system"): BLOCK, ("chown", "home"): REVIEW,
    ("chown", "root"): BLOCK, ("chown", "outside"): REVIEW,
    # reads (secret handling layered on top)
    ("read", "project"): ALLOW, ("read", "home"): ALLOW, ("read", "system"): ALLOW,
    ("read", "outside"): ALLOW, ("read", "tmp"): ALLOW, ("read", "null"): ALLOW,
    ("read", "device"): REVIEW, ("read", "home_root"): ALLOW,
}


def _sev(verb: str, scope: str) -> str:
    if (verb, scope) in _SEVERITY:
        return _SEVERITY[(verb, scope)]
    if scope in ("unknown", "unknown_root"):
        return REVIEW if verb in _MUTATING else ALLOW
    return REVIEW if verb in _MUTATING else ALLOW


# --------------------------------------------------------------------------- #
# analyser
# --------------------------------------------------------------------------- #

@dataclass
class _Ctx:
    cwd: str
    project_root: Optional[str]
    home: Optional[str]
    env: dict
    funcs: set
    depth: int = 0


class _Analyzer:
    def __init__(self, report: Report, ctx: _Ctx):
        self.r = report
        self.ctx = ctx

    # ---- public ---- #
    def run(self, script: Script) -> None:
        self._collect_functions(script)
        self._walk(script)

    def _is_fork_bomb(self, c: Compound) -> bool:
        """A function whose body spawns itself (pipe or background) with no base case."""
        name = c.name
        self_calls = backgrounded = piped = False

        def scan(script: Script):
            nonlocal self_calls, backgrounded, piped
            for ao in script.items:
                if ao.background:
                    backgrounded = True
                for pl in ao.pipelines:
                    if len(pl.commands) > 1:
                        piped = True
                    for cmd in pl.commands:
                        if isinstance(cmd, SimpleCommand) and cmd.words and cmd.words[0].is_static:
                            if cmd.words[0].value == name:
                                self_calls = True
                        elif isinstance(cmd, Compound):
                            for b in cmd.bodies:
                                scan(b)
        for b in c.bodies:
            scan(b)
        return self_calls and (backgrounded or piped)

    def _collect_functions(self, script: Script) -> None:
        for ao in script.items:
            for pl in ao.pipelines:
                for cmd in pl.commands:
                    if isinstance(cmd, Compound) and cmd.kind == "function" and cmd.name:
                        self.ctx.funcs.add(cmd.name)

    # ---- traversal ---- #
    def _walk(self, script: Script) -> None:
        for ao in script.items:
            for pl in ao.pipelines:
                self._flag_pipe_to_shell(pl)
                for cmd in pl.commands:
                    self._command(cmd)

    def _flag_pipe_to_shell(self, pl) -> None:
        names = []
        for cmd in pl.commands:
            if isinstance(cmd, SimpleCommand) and cmd.words and cmd.words[0].is_static:
                names.append(self._effective_shell(cmd.words))
            else:
                names.append(None)
        for i in range(len(names) - 1):
            if names[i] in _DOWNLOADERS and names[i + 1] in _SHELLS:
                self.r.add("pipe-to-shell", BLOCK,
                           f"`{names[i]} … | {names[i+1]}` pipes a network download straight into an "
                           f"interpreter — it runs remote code with no chance to inspect it.")

    @staticmethod
    def _effective_shell(words) -> Optional[str]:
        """First program name, seeing through sudo/env/nohup/timeout wrappers."""
        i = 0
        while i < len(words) and words[i].is_static:
            name = words[i].value.rsplit("/", 1)[-1]
            if name in ("sudo", "doas", "env", "nohup", "setsid", "timeout", "nice", "stdbuf",
                        "ionice", "xargs"):
                i += 1
                while i < len(words) and words[i].is_static and words[i].value.startswith("-"):
                    i += 1
                if name in ("env", "timeout"):  # skip VAR=val / duration
                    while i < len(words) and words[i].is_static and (
                            "=" in words[i].value or words[i].value.replace(".", "").rstrip("s").isdigit()):
                        i += 1
                continue
            return name
        return words[0].value.rsplit("/", 1)[-1] if words and words[0].is_static else None

    def _command(self, cmd) -> None:
        if isinstance(cmd, Compound):
            return self._compound(cmd)
        self._simple(cmd)

    def _compound(self, c: Compound) -> None:
        if c.kind == "function":
            if c.name and self._is_fork_bomb(c):
                self.r.add("fork-bomb", BLOCK,
                           f"`{c.name}()` calls itself in the background in a loop — a fork bomb that "
                           f"exhausts the process table and freezes the machine.")
            return  # defined, not run; body analysed if/when invoked by name below
        # loop item words and case subjects can carry substitutions
        for w in c.words:
            self._word_side_effects(w, program=c.kind)
        for body in c.bodies:
            self._walk(body)
        for red in c.redirects:
            self._redirect(red, program=c.kind)

    # ---- simple command ---- #
    def _simple(self, cmd: SimpleCommand) -> None:
        # assignments: track static ones, note dynamic ones
        for name, val in cmd.assignments:
            if val.is_static:
                self.ctx.env[name] = val.value
            else:
                self.ctx.env.pop(name, None)
            for s in val.subs:
                self._subscript(s, "assignment")

        for red in cmd.redirects:
            self._redirect(red, program=(cmd.words[0].approx() if cmd.words else "redirect"))

        if not cmd.words:
            return

        head = cmd.words[0]
        # substitutions inside every word always run
        for w in cmd.words:
            self._word_side_effects(w, program="(substitution)")

        name = self._resolve_name(head)
        if name is None:
            self.r.dynamic = True
            self.r.add("dynamic-program", REVIEW,
                       f"Program name is computed at runtime ({head.approx()}); its effects can't be checked statically.")
            return

        if name in self.ctx.funcs:
            return  # user-defined function; body already walked where defined

        self.r.programs.append(name)
        self._apply_tool(name, cmd)

    def _resolve_name(self, w: Word) -> Optional[str]:
        if w.is_static:
            return w.value
        # single $VAR we know statically
        if len(w.parts) == 1 and w.parts[0][0] == "var":
            v = w.parts[0][1]
            key = v if isinstance(v, str) else v[0]
            if key in self.ctx.env:
                return self.ctx.env[key]
        return None

    # ---- apply a tool spec ---- #
    def _apply_tool(self, name: str, cmd: SimpleCommand):
        spec = tools.lookup(name)
        base = name.rsplit("/", 1)[-1]

        if base in tools.HARMLESS_BUILTINS and spec.get("unknown"):
            return

        # operands / flags
        operands, flags, run_rest, output_targets = self._split_args(spec, cmd.words[1:])

        if spec.get("privileged"):
            self.r.add("privilege", REVIEW,
                       f"`{base}` runs with elevated privileges; effects below apply as root.")
        if base == "sudo" or spec.get("env_prefix") or (spec.get("runs_rest") and run_rest):
            self._run_delegated(base, run_rest, spec)
            if base in ("sudo", "doas", "env", "nohup", "setsid", "timeout", "nice", "ionice",
                        "stdbuf", "time", "watch", "xargs", "npx", "chrt"):
                return

        if spec.get("interp") or spec.get("eval_builtin") or spec.get("exec_builtin"):
            self._interpreter(base, spec, cmd.words[1:], operands, flags)

        if spec.get("network"):
            # package managers only reach the network on install-like subcommands
            pkg_net = True
            if base in _PKG_MANAGERS:
                sub = next((w.value for w in operands if w.is_static and not w.value.startswith("-")), None)
                pkg_net = sub is None or sub in _PKG_NET_SUBCMDS
            if pkg_net:
                self._network(base, spec, operands, flags, output_targets)
                if spec.get("package"):
                    self._package(base, operands)
            if not spec.get("download"):
                return

        if spec.get("package"):
            self._package(base, operands)
            return

        if spec.get("git"):
            return self._git(cmd.words[1:])
        if spec.get("cd"):
            return self._chdir(operands)
        if base == "crontab":
            self.r.add("crontab", REVIEW,
                       "`crontab` changes scheduled jobs that run automatically later.")
            return
        if spec.get("kill") == ["kill"] or "kill" in spec.get("effects", []):
            self.r.add("kill", REVIEW, f"`{base}` terminates other processes.")
            return
        if "mount" in spec.get("effects", []):
            self.r.add("mount", BLOCK, f"`{base}` changes mounted filesystems.")
            return
        if spec.get("device_op"):
            self._device_op(base, operands)
            return
        if spec.get("dd"):
            return self._dd(base, cmd.words[1:])
        if spec.get("tar"):
            return self._tar(base, cmd.words[1:])
        if spec.get("find"):
            return self._find(base, cmd.words[1:])

        self._filesystem(base, spec, operands, flags, output_targets)

    # ---- argument splitting ---- #
    def _split_args(self, spec: dict, args: list):
        operands: list[Word] = []
        flags: set = set()
        takes = spec.get("takes_value", set())
        run_rest: list[Word] = []
        output_targets: list[Word] = []
        output_flags = spec.get("output_flags", set())
        i = 0
        saw_dd = spec.get("dd")
        while i < len(args):
            w = args[i]
            tok = w.value if w.is_static else w.approx()
            if tok == "--":
                operands.extend(args[i + 1:])
                break
            if tok.startswith("-") and len(tok) > 1 and not saw_dd:
                bare = tok.split("=", 1)[0]
                flags.add(bare)
                # decompose bundled short flags: -rf -> -r, -f (so -rf counts as recursive+force)
                if not bare.startswith("--") and bare[1:].isalpha():
                    for ch in bare[1:]:
                        flags.add("-" + ch)
                if "=" not in tok and bare in takes and i + 1 < len(args):
                    if bare in output_flags:
                        output_targets.append(args[i + 1])
                    i += 2
                    continue
                if "=" in tok and bare in output_flags:
                    output_targets.append(Word(raw=tok.split("=", 1)[1],
                                               parts=[("lit", tok.split("=", 1)[1])]))
                i += 1
                continue
            operands.append(w)
            i += 1
        if spec.get("runs_rest"):
            run_rest = operands
        return operands, flags, run_rest, output_targets

    # ---- filesystem effects ---- #
    def _filesystem(self, base: str, spec: dict, operands, flags, output_targets):
        effects = spec.get("effects", ["read"])
        recursive = bool(spec.get("recursive_flags", set()) & flags)
        forced = bool(spec.get("force_flags", set()) & flags)
        role = spec.get("operand_role", "all")
        unknown = spec.get("unknown")

        # inplace flag flips a read tool into a mutator (sed -i, perl -i)
        if spec.get("inplace_flags") and (spec["inplace_flags"] & flags):
            effects = [spec["inplace_effect"]]

        if role == "none" and not output_targets:
            return

        ops = list(operands)
        if spec.get("skip_first_operand") and ops and not unknown:
            # e.g. grep PATTERN file...  / chmod MODE file... / sed SCRIPT file...
            ops = ops[1:]

        if role == "last_is_dest" and len(ops) >= 1:
            *sources, dest = ops
            for s in sources:
                self._emit(spec.get("reads_operands", "read"), s, base, recursive, forced)
            self._emit(spec.get("dest_effect", "create"), dest, base, recursive, forced)
        elif role == "first" and ops:
            self._emit(effects[0], ops[0], base, recursive, forced)
        else:
            for op in ops:
                for verb in effects:
                    self._emit(verb, op, base, recursive, forced)

        for ot in output_targets:
            self._emit("write", ot, base, recursive, forced)

        if unknown and not spec.get("network") and base not in tools.COMMON_DEV_TOOLS:
            self.r.add("unknown-tool", ALLOW,
                       f"`{base}` isn't a recognised tool; assuming it only reads its arguments as files.")

    def _emit(self, verb: str, w: Word, program: str, recursive: bool, forced: bool):
        """Create an Effect for a verb acting on a word that denotes a path."""
        shown = self._expand_shown(w)
        base_path, has_glob, broad = paths.split_glob(shown) if w.is_static or self._mostly_static(w) else (shown, False, False)
        if not (w.is_static or self._mostly_static(w)):
            vpath = None
        else:
            vpath = paths.to_virtual(base_path, self.ctx.cwd, self.ctx.project_root, self.ctx.home)
            if has_glob and vpath is not None:
                vpath = vpath  # directory the glob scans
        tgt = paths.classify(shown, vpath, broad=broad)
        # a glob whose base is the project root (`*.pyc`, `build/*`) acts on matches
        # INSIDE the directory, not on the directory itself — don't treat as project_root.
        if has_glob and tgt.scope == "project_root" and vpath:
            tgt = paths.classify(shown, vpath.rstrip("/") + "/__glob__", broad=broad)
        eff = Effect(verb=verb, target=tgt, program=program, recursive=recursive, forced=forced)
        self.r.effects.append(eff)

        last = shown.rstrip("/").rsplit("/", 1)[-1]
        ephemeral = last in _EPHEMERAL_DIRS

        sev = _sev(verb, tgt.scope)
        # ---- delete escalations ---- #
        if verb == "delete":
            if tgt.scope in ("home", "home_root", "outside", "system", "root", "device"):
                sev = _bump(sev, BLOCK)
            elif tgt.scope == "project_root":
                sev = _bump(sev, BLOCK)       # deleting the project dir itself
            elif tgt.scope == "project":
                if ephemeral:
                    sev = ALLOW               # rm -rf build/ node_modules/ — routine
                elif recursive or tgt.broad:
                    sev = _bump(sev, REVIEW)
                else:
                    sev = ALLOW               # deleting one project file is routine
            elif tgt.scope == "tmp":
                sev = ALLOW
        # ---- move: an in-project rename is routine; leaving the project is not ---- #
        if verb == "move":
            if tgt.scope == "project":
                sev = ALLOW
            elif tgt.scope == "project_root":
                sev = _bump(sev, BLOCK)
        if verb == "create" and tgt.scope == "project":
            sev = ALLOW
        # ---- critical system files ---- #
        if verb in _MUTATING and (tgt.shown in _CRITICAL_SYSTEM or
                                  any(tgt.shown.startswith(p) for p in _CRITICAL_PREFIXES) or
                                  (vpath and (vpath in _CRITICAL_SYSTEM or
                                   any(vpath.startswith(p) for p in _CRITICAL_PREFIXES)))):
            sev = BLOCK
            self.r.add("critical-system-file", BLOCK,
                       f"`{program}` {verb}s {tgt.shown}, a critical system file; this can break "
                       f"login, boot or privilege rules.", eff)
            return
        if tgt.autorun and verb in _MUTATING:
            sev = _bump(sev, REVIEW)
            self.r.add("autorun-write", sev,
                       f"`{program}` {verb}s {shown}, which runs automatically later (shell start-up, hook or scheduler).",
                       eff)
            return
        if tgt.secret and verb == "read":
            sev = _bump(sev, REVIEW)
            self.r.add("secret-read", sev,
                       f"`{program}` reads {shown}, which usually holds credentials.", eff)
            return
        if tgt.secret and verb in _MUTATING and tgt.scope not in ("project", "project_root", "tmp"):
            sev = _bump(sev, REVIEW)

        if tgt.is_git_dir and verb in _MUTATING:
            sev = _bump(sev, REVIEW)
            self.r.add("git-internals", sev,
                       f"`{program}` {verb}s the .git directory; this can corrupt history.", eff)
            return

        msg = self._describe(verb, tgt, recursive, forced, program)
        code = f"{verb}-{tgt.scope}"
        if sev != ALLOW:
            self.r.add(code, sev, msg, eff)

    def _describe(self, verb: str, t: paths.Target, recursive: bool, forced: bool, program: str) -> str:
        where = {
            "project": "inside the project", "project_root": "the whole project directory",
            "home": "in your home directory", "home_root": "your entire home directory",
            "system": "a system location", "root": "the filesystem root",
            "outside": "outside the project", "tmp": "a temp directory", "device": "a device file",
            "unknown": "a path that can't be resolved", "null": "a null device",
        }.get(t.scope, t.scope)
        rec = "recursively " if recursive else ""
        extra = " broadly (glob matches everything)" if t.broad else ""
        return f"`{program}` {rec}{verb}s {t.shown} — {where}{extra}."

    # ---- interpreters & eval ---- #
    def _interpreter(self, base: str, spec: dict, args: list, operands, flags):
        runs_flag = spec.get("runs_flag")
        code_word = None
        if runs_flag:
            for i, w in enumerate(args):
                tok = w.value if w.is_static else w.approx()
                if tok == runs_flag and i + 1 < len(args):
                    code_word = args[i + 1]
                    break
                if tok.startswith(runs_flag + "="):
                    code_word = Word(raw=tok[len(runs_flag) + 1:], parts=[("lit", tok[len(runs_flag) + 1:])])
                    break
        if spec.get("eval_builtin"):
            # eval STRING / source FILE
            code_word = operands[0] if operands else None
            if base in (".", "source"):
                if code_word:
                    self._emit("read", code_word, base, False, False)
                self.r.add("source", REVIEW,
                           f"`{base}` executes another script in this shell; its effects depend on that file.")
                return

        if base in ("sh", "bash", "dash", "zsh", "ksh"):
            if code_word is None:
                # bash FILE or bash reading stdin
                if operands:
                    self._emit("read", operands[0], base, False, False)
                    self.r.add("run-script", REVIEW,
                               f"`{base}` runs the script {self._expand_shown(operands[0])}; its effects depend on that file.")
                else:
                    self.r.dynamic = True
                    self.r.add("shell-stdin", REVIEW,
                               f"`{base}` runs commands from standard input (often a piped download); effects can't be seen.")
                return

        if code_word is not None:
            if code_word.is_static:
                inner = code_word.value
                if base in ("sh", "bash", "dash", "zsh", "ksh"):
                    self._subcommand(inner, f"{base} -c")
                else:
                    self._inline_code(base, inner)
            else:
                self.r.dynamic = True
                # bash -c "$(curl …)" / eval of a download — remote code execution
                if any(self._script_has_downloader(s) for s in code_word.subs):
                    self.r.add("exec-remote-code", BLOCK,
                               f"`{base} -c` executes the output of a network download — it runs "
                               f"remote code with no chance to inspect it.")
                else:
                    self.r.add("dynamic-code", REVIEW,
                               f"`{base}` runs code assembled at runtime ({code_word.approx()}); effects can't be seen.")
                    # still analyse any substitutions for their own effects
                    for s in code_word.subs:
                        self._subscript(s, f"{base} -c")
            return

        if spec.get("eval_builtin"):
            self.r.dynamic = True
            self.r.add("eval", REVIEW, "`eval` runs a string as a command; effects depend on runtime values.")

    def _inline_code(self, base: str, code: str):
        """Heuristic scan of inline python/node/etc. for obvious dangerous calls."""
        dangerous = [
            ("os.system", "shell command"), ("subprocess.", "subprocess"),
            ("shutil.rmtree", "recursive delete"), ("os.remove", "file delete"),
            ("os.unlink", "file delete"), ("Popen", "subprocess"),
            ("socket.", "network socket"), ("urllib", "network request"),
            ("requests.", "network request"), ("child_process", "subprocess"),
            ("execSync", "subprocess"), ("eval(", "dynamic eval"), ("exec(", "dynamic exec"),
            ("__import__", "dynamic import"), ("fs.unlink", "file delete"),
            ("fs.rm", "file delete"), ("open(", "file access"),
        ]
        hits = sorted({d[1] for d in dangerous if d[0] in code})
        self.r.dynamic = True
        if hits:
            sev = BLOCK if any(h in ("recursive delete", "shell command", "subprocess") for h in hits) else REVIEW
            self.r.add("inline-code", sev,
                       f"Inline `{base}` code performs: {', '.join(hits)}. Review the script body.")
        # harmless inline code (print, arithmetic, no I/O) is routine — don't flag.

    def _subcommand(self, src: str, label: str):
        if self.ctx.depth > 12:
            self.r.dynamic = True
            return
        try:
            sub = parse(src)
        except ParseError:
            self.r.dynamic = True
            self.r.add("unparsed-subcommand", REVIEW,
                       f"`{label}` runs a command that couldn't be parsed; review it manually.")
            return
        child = _Analyzer(self.r, _Ctx(self.ctx.cwd, self.ctx.project_root, self.ctx.home,
                                       dict(self.ctx.env), set(self.ctx.funcs), self.ctx.depth + 1))
        child.run(sub)

    def _subscript(self, script: Script, label: str):
        child = _Analyzer(self.r, _Ctx(self.ctx.cwd, self.ctx.project_root, self.ctx.home,
                                       dict(self.ctx.env), set(self.ctx.funcs), self.ctx.depth + 1))
        child._walk(script)

    def _run_delegated(self, base: str, run_rest, spec):
        # sudo CMD..., env CMD..., xargs CMD..., timeout N CMD...
        rest = list(run_rest)
        # strip leading VAR=val for env, and numeric duration for timeout
        while rest:
            tok = rest[0].value if rest[0].is_static else rest[0].approx()
            if base == "env" and "=" in tok and not tok.startswith("-"):
                rest = rest[1:]
                continue
            if base in ("timeout", "nice", "sleep") and tok.replace(".", "").replace("s", "").isdigit():
                rest = rest[1:]
                continue
            if tok.startswith("-"):
                rest = rest[1:]
                continue
            break
        if not rest:
            return
        synthetic = SimpleCommand(assignments=[], words=rest, redirects=[])
        self._simple(synthetic)

    # ---- networks / downloads ---- #
    def _network(self, base: str, spec: dict, operands, flags, output_targets):
        piped = self._downloads_into_shell(base)
        self.r.add("network", REVIEW if not piped else BLOCK,
                   f"`{base}` contacts the network." +
                   (" Output is piped straight into a shell — remote code execution." if piped else ""))
        for ot in output_targets:
            self._emit("write", ot, base, False, False)

    def _downloads_into_shell(self, base: str) -> bool:
        return False  # pipeline-level detection handled in analyze() wrapper

    def _package(self, base: str, operands=()):
        sub = next((w.value for w in operands if w.is_static and not w.value.startswith("-")), None)
        if base in _PKG_MANAGERS and sub is not None and sub not in _PKG_NET_SUBCMDS:
            return
        self.r.add("package-install", REVIEW,
                   f"`{base}` installs packages from the network; it can run install-time code.")

    # ---- specific tools ---- #
    def _git(self, args: list):
        sub = None
        for w in args:
            tok = w.value if w.is_static else None
            if tok and not tok.startswith("-"):
                sub = tok
                break
        dangerous = {
            "push": (REVIEW, "pushes commits to a remote — a network-visible, hard-to-undo action."),
            "reset": (REVIEW, "can discard committed or staged work (especially `--hard`)."),
            "clean": (REVIEW, "deletes untracked files."),
            "checkout": (ALLOW, "switches branches/files."),
            "rebase": (REVIEW, "rewrites commit history."),
            "filter-branch": (BLOCK, "rewrites the entire history."),
            "gc": (ALLOW, "repacks the repo."),
            "config": (REVIEW, "changes git configuration."),
        }
        if sub == "push" and any((w.value or "") == "--force" or (w.value or "").startswith("--force") or
                                 (w.value or "") == "-f" for w in args):
            self.r.add("git-force-push", BLOCK, "`git push --force` can overwrite remote history for others.")
            return
        if sub == "reset" and any((w.value or "") == "--hard" for w in args):
            self.r.add("git-reset-hard", REVIEW, "`git reset --hard` discards uncommitted changes irreversibly.")
            return
        if sub in dangerous:
            sev, why = dangerous[sub]
            if sev != ALLOW:
                self.r.add(f"git-{sub}", sev, f"`git {sub}` {why}")

    def _chdir(self, operands):
        if operands and operands[0].is_static:
            target = paths.to_virtual(operands[0].value, self.ctx.cwd, self.ctx.project_root, self.ctx.home)
            if target:
                self.ctx.cwd = target

    def _dd(self, base: str, args: list):
        out = None
        for w in args:
            tok = w.value if w.is_static else w.approx()
            if tok.startswith("of="):
                out = Word(raw=tok[3:], parts=[("lit", tok[3:])])
        if out is not None:
            tgt = self._target_for(out)
            eff = Effect("write", tgt, base, False, True)
            self.r.effects.append(eff)
            if tgt.scope in ("device", "system", "root", "home_root") or tgt.shown.startswith("/dev/"):
                self.r.add("dd-write", BLOCK,
                           f"`dd` writes raw bytes to {tgt.shown} ({self._scope_phrase(tgt.scope)}); "
                           f"on a device or disk this destroys data irrecoverably.", eff)
            else:
                sev = _sev("write", tgt.scope)
                if sev != ALLOW:
                    self.r.add("dd-write", sev, f"`dd` writes raw bytes to {tgt.shown}.", eff)
        else:
            self.r.add("dd", REVIEW, "`dd` copies raw bytes; check its `of=` target.")

    def _tar(self, base: str, args: list):
        creating = extracting = False
        outfile = None
        changedir = None
        i = 0
        while i < len(args):
            tok = args[i].value if args[i].is_static else args[i].approx()
            if tok.startswith("-"):
                if "c" in tok:
                    creating = True
                if "x" in tok:
                    extracting = True
                if tok in ("-C", "--directory") and i + 1 < len(args):
                    changedir = args[i + 1]
                    i += 2
                    continue
                if tok in ("-f", "--file") and i + 1 < len(args):
                    outfile = args[i + 1]
                    i += 2
                    continue
            elif i == 0 and not tok.startswith("-"):
                if "c" in tok:
                    creating = True
                if "x" in tok:
                    extracting = True
            i += 1
        if extracting:
            where = changedir or Word(raw=".", parts=[("lit", ".")])
            self._emit("create", where, base, True, False)
            self.r.add("tar-extract", REVIEW if changedir and not self._in_project(changedir) else ALLOW,
                       "`tar -x` extracts an archive; a crafted archive can write outside the target via `..` or absolute paths.")
        elif creating and outfile is not None:
            self._emit("create", outfile, base, False, False)

    def _find(self, base: str, args: list):
        """`find` roots are read; `-delete`/`-exec`/`-execdir`/`-ok` are actions on matches."""
        roots: list[Word] = []
        i = 0
        # leading non-option operands are search roots
        while i < len(args):
            tok = args[i].value if args[i].is_static else args[i].approx()
            if tok.startswith("-") or tok in ("(", ")", "!") or tok.startswith("("):
                break
            roots.append(args[i])
            i += 1
        if not roots:
            roots = [Word(raw=".", parts=[("lit", ".")])]
        for root in roots:
            self._emit("read", root, base, True, False)

        # scan the expression for actions
        while i < len(args):
            tok = args[i].value if args[i].is_static else args[i].approx()
            if tok == "-delete":
                for root in roots:
                    tgt = self._target_for(root)
                    eff = Effect("delete", tgt, base, True, True)
                    self.r.effects.append(eff)
                    scope = tgt.scope
                    # -delete removes MATCHES under the root, not the root dir itself
                    if scope == "project_root":
                        scope = "project"
                    sev = _sev("delete", scope)
                    if scope in ("home", "home_root", "outside", "system", "root"):
                        sev = BLOCK
                    elif scope == "project":
                        sev = REVIEW
                    if sev != ALLOW:
                        self.r.add("find-delete", sev,
                                   f"`find … -delete` removes every match under {self._expand_shown(root)} "
                                   f"({self._scope_phrase(scope)}).", eff)
            elif tok in ("-exec", "-execdir", "-ok", "-okdir"):
                # collect command up to ';' or '+'
                j = i + 1
                sub_words = []
                while j < len(args):
                    t2 = args[j].value if args[j].is_static else args[j].approx()
                    if t2 in (";", "+", "\\;"):
                        break
                    sub_words.append(args[j])
                    j += 1
                if sub_words:
                    synthetic = SimpleCommand(assignments=[], words=sub_words, redirects=[])
                    exec_name = sub_words[0].value if sub_words[0].is_static else ""
                    root_scopes = {self._target_for(r2).scope for r2 in roots}
                    dangerous_root = bool(root_scopes & {"root", "system", "home_root", "home"})
                    destructive = exec_name.rsplit("/", 1)[-1] in ("rm", "rmdir", "shred", "unlink",
                                                                    "mv", "chmod", "chown", "dd")
                    if dangerous_root and destructive:
                        self.r.add("find-exec-dangerous", BLOCK,
                                   f"`find {'/'.join(sorted(root_scopes))} … {tok} {exec_name}` runs a "
                                   f"destructive command on every match across a system or home tree.")
                    else:
                        self.r.add("find-exec", REVIEW,
                                   f"`find … {tok}` runs a command on every match; its effect is shown below.")
                    self._simple(synthetic)
                i = j
            i += 1

    def _script_has_downloader(self, script: Script) -> bool:
        for ao in script.items:
            for pl in ao.pipelines:
                for cmd in pl.commands:
                    if isinstance(cmd, SimpleCommand) and cmd.words and cmd.words[0].is_static:
                        if cmd.words[0].value.rsplit("/", 1)[-1] in _DOWNLOADERS:
                            return True
        return False

    def _target_for(self, w: Word):
        shown = self._expand_shown(w)
        base_path, has_glob, broad = paths.split_glob(shown)
        vpath = paths.to_virtual(base_path, self.ctx.cwd, self.ctx.project_root, self.ctx.home) \
            if (w.is_static or self._mostly_static(w)) else None
        return paths.classify(shown, vpath, broad=broad)

    def _scope_phrase(self, scope: str) -> str:
        return {"project": "inside the project", "project_root": "the whole project",
                "home": "in your home directory", "home_root": "your entire home directory",
                "system": "a system location", "root": "the filesystem root",
                "outside": "outside the project", "tmp": "a temp directory",
                "unknown": "an unresolved path"}.get(scope, scope)

    def _device_op(self, base: str, operands):
        for op in operands:
            if op.is_static and op.value.startswith("/dev/"):
                eff = Effect("write", paths.classify(op.value, op.value), base, False, True)
                self.r.effects.append(eff)
                self.r.add("device-write", BLOCK,
                           f"`{base}` writes to the block device {op.value}; this destroys its contents.", eff)
                return
        self.r.add("device-op", REVIEW, f"`{base}` operates on disks/partitions.")

    def _in_project(self, w: Word) -> bool:
        if not w.is_static:
            return False
        v = paths.to_virtual(w.value, self.ctx.cwd, self.ctx.project_root, self.ctx.home)
        return bool(v and (v == paths.PROJECT or v.startswith(paths.PROJECT + "/")))

    # ---- redirects & substitutions ---- #
    def _redirect(self, red, program: str):
        if red.heredoc is not None:
            for s in red.heredoc_subs:
                self._subscript(s, "heredoc")
            return
        if red.op in ("<", "<&", "<<<"):
            if red.target and red.op == "<":
                self._emit("read", red.target, program, False, False)
            return
        if red.target is None:
            return
        verb = "write"
        self._emit(verb, red.target, program, False, red.op in (">", ">|", "&>"))

    def _word_side_effects(self, w: Word, program: str):
        for s in w.subs:
            self._subscript(s, program)

    # ---- helpers ---- #
    def _expand_shown(self, w: Word) -> str:
        """Human-facing path string, with known vars substituted."""
        out = []
        for kind, payload in w.parts:
            if kind in ("lit", "glob"):
                out.append(payload)
            elif kind == "tilde":
                out.append((self.ctx.home or "~") + ("" if payload else ""))
            elif kind == "var":
                key = payload if isinstance(payload, str) else payload[0]
                if key in self.ctx.env:
                    out.append(self.ctx.env[key])
                elif key == "HOME" and self.ctx.home:
                    out.append(self.ctx.home)
                elif key == "PWD":
                    out.append(self.ctx.cwd)
                else:
                    out.append("$" + key)
            elif kind == "cmd":
                out.append("$(…)")
            elif kind == "arith":
                out.append("$((…))")
        return "".join(out)

    def _mostly_static(self, w: Word) -> bool:
        """A path is 'mostly static' if only a known $HOME/$PWD/known-var is involved."""
        for kind, payload in w.parts:
            if kind in ("lit", "glob", "tilde"):
                continue
            if kind == "var":
                key = payload if isinstance(payload, str) else payload[0]
                if key in self.ctx.env or key in ("HOME", "PWD"):
                    continue
            return False
        return True


def _bump(cur: str, to: str) -> str:
    return to if _SEV_ORDER[to] > _SEV_ORDER[cur] else cur


# --------------------------------------------------------------------------- #
# public entry point
# --------------------------------------------------------------------------- #

def analyze(command: str, project_root: Optional[str] = ".", home: Optional[str] = None,
            cwd: Optional[str] = None, env: Optional[dict] = None) -> Report:
    """Analyse one shell command. ``project_root`` is the agent's working directory."""
    import os
    home = home if home is not None else os.path.expanduser("~")
    project_root = os.path.abspath(project_root) if project_root else None
    cwd_v = paths.PROJECT if project_root else "/__out__"

    report = Report(command=command)
    report.env = {"project_root": project_root, "home": home}

    try:
        script = parse(command)
    except ParseError as e:
        report.parse_ok = False
        report.parse_error = str(e)
        report.dynamic = True
        report.add("parse-error", REVIEW,
                   f"Command could not be parsed ({e}); run it only after manual review.")
        return report

    ctx = _Ctx(cwd=cwd_v, project_root=project_root, home=home,
               env=dict(env or {}), funcs=set())
    _Analyzer(report, ctx).run(script)
    return report


_DOWNLOADERS = {"curl", "wget", "fetch", "http", "https"}
_SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "fish", "python", "python3", "node", "ruby", "perl"}
_PKG_MANAGERS = {"npm", "pnpm", "yarn", "bun"}
# subcommands for npm/yarn/pnpm that actually hit the network / run install hooks
_PKG_NET_SUBCMDS = {"install", "i", "ci", "add", "update", "up", "upgrade", "publish", "audit",
                    "exec", "dlx", "create", "init", "link", "rebuild", "fund", "dedupe"}
# directories agents routinely wipe; recursive deletes here are noise, not risk
_EPHEMERAL_DIRS = {"build", "dist", "out", "target", "node_modules", "__pycache__", ".pytest_cache",
                   ".mypy_cache", ".ruff_cache", ".cache", "coverage", ".coverage", ".next", ".nuxt",
                   ".svelte-kit", ".turbo", ".parcel-cache", "tmp", "temp", ".tox", ".venv", "venv",
                   ".gradle", "bin", "obj", ".terraform", "htmlcov", ".eggs", "vendor"}
# writing these makes a machine insecure or unbootable: always block
_CRITICAL_SYSTEM = {"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/fstab", "/etc/crontab",
                    "/etc/hosts.deny", "/etc/ssh/sshd_config", "/etc/environment", "/boot"}
_CRITICAL_PREFIXES = ("/etc/sudoers.d", "/etc/cron", "/var/spool/cron", "/boot/", "/etc/pam.d")
