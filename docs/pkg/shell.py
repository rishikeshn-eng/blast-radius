"""A small, security-oriented parser for POSIX/bash command lines.

The goal is not to execute bash. It is to recover, as faithfully as a static
reader can, *which programs a command line will run and with which arguments*,
including programs hidden inside quotes, substitutions, heredocs, `eval`
strings and compound statements. Anything we cannot resolve statically is
marked dynamic so the analyser can fail closed.

Supported: quoting (single, double, ANSI-C ``$'..'``, backslash), parameter
expansion, ``$(..)``, backticks, ``$((..))``, process substitution, globs,
brace words, every redirection form bash accepts, heredocs (``<<``, ``<<-``,
``<<<``), pipelines, ``&&``/``||``/``;``/``&``, subshells, groups, ``if``,
``for``, ``while``/``until``, ``case``, ``[[ .. ]]``, ``(( .. ))``, functions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Union

__all__ = [
    "ParseError", "Word", "Redirect", "SimpleCommand", "Compound", "Pipeline",
    "AndOr", "Script", "parse",
]


class ParseError(ValueError):
    """Raised when a command line cannot be parsed. Callers should fail closed."""


# --------------------------------------------------------------------------- #
# AST
# --------------------------------------------------------------------------- #

@dataclass
class Word:
    """One shell word after quote removal, with enough metadata to reason about it."""

    raw: str                                  # source text, exactly as written
    parts: list = field(default_factory=list)  # ("lit"|"var"|"cmd"|"arith"|"glob"|"tilde", payload)
    quoted: bool = False                       # any part was quoted

    # -- derived views ----------------------------------------------------- #
    @property
    def subs(self) -> list["Script"]:
        """Command / process substitutions nested in this word (in order)."""
        out = []
        for kind, payload in self.parts:
            if kind == "cmd":
                out.append(payload)
            elif kind == "var" and isinstance(payload, tuple):
                # ${X:-$(cmd)} -> nested words carry their own substitutions
                for w in payload[1]:
                    out.extend(w.subs)
        return out

    @property
    def is_static(self) -> bool:
        """True when the word's value is fully known without running anything."""
        return all(kind in ("lit", "glob") for kind, _ in self.parts)

    @property
    def value(self) -> Optional[str]:
        """Literal value when static, else ``None``."""
        if not self.is_static:
            return None
        return "".join(p for _, p in self.parts)

    @property
    def has_glob(self) -> bool:
        return any(kind == "glob" for kind, _ in self.parts)

    def approx(self) -> str:
        """Best-effort printable value: expansions are shown as ``$NAME`` / ``$(..)``."""
        out = []
        for kind, payload in self.parts:
            if kind in ("lit", "glob"):
                out.append(payload)
            elif kind == "tilde":
                out.append("~" + payload)
            elif kind == "var":
                name = payload[0] if isinstance(payload, tuple) else payload
                out.append("$" + name)
            elif kind == "cmd":
                out.append("$(…)")
            elif kind == "arith":
                out.append("$((…))")
        return "".join(out)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Word({self.raw!r})"


@dataclass
class Redirect:
    op: str                       # '>', '>>', '<', '<>', '>|', '&>', '&>>', '>&', '<&', '<<', '<<-', '<<<'
    fd: Optional[int]
    target: Optional[Word]        # None for heredocs
    heredoc: Optional[str] = None  # body text for << and <<-
    heredoc_quoted: bool = False   # delimiter was quoted -> no expansion in body
    heredoc_subs: list = field(default_factory=list)


@dataclass
class SimpleCommand:
    assignments: list            # list[tuple[str, Word]]
    words: list                  # list[Word]
    redirects: list              # list[Redirect]
    start: int = 0
    end: int = 0


@dataclass
class Compound:
    kind: str                    # subshell | group | if | for | while | until | case | arith | cond | function
    bodies: list                 # list[Script]
    words: list = field(default_factory=list)   # loop items, case subject, [[ ]] words
    redirects: list = field(default_factory=list)
    name: Optional[str] = None   # loop variable / function name
    start: int = 0
    end: int = 0


Command = Union[SimpleCommand, Compound]


@dataclass
class Pipeline:
    commands: list               # list[Command]
    negated: bool = False


@dataclass
class AndOr:
    pipelines: list              # list[Pipeline]
    ops: list                    # '&&' / '||' between pipelines
    background: bool = False     # terminated by '&'


@dataclass
class Script:
    items: list                  # list[AndOr]
    source: str = ""


# --------------------------------------------------------------------------- #
# Lexer + recursive-descent parser (single pass over characters)
# --------------------------------------------------------------------------- #

_META = set(" \t\n|&;()<>")
_RESERVED_START = {"if", "for", "while", "until", "case", "{", "!", "[[", "function", "select"}
_RESERVED_ANY = _RESERVED_START | {"then", "elif", "else", "fi", "do", "done", "esac", "in", "}", "]]"}
_ANSI_C = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b",
           "f": "\f", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}
_REDIR_OPS = ["&>>", "<<<", "<<-", "&>", ">>", "<<", ">&", "<&", "<>", ">|", ">", "<"]
_MAX_DEPTH = 40
_PARAM_NAME = re.compile(r"[#!]?(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-])")


@dataclass
class _Tok:
    kind: str                  # 'word' | 'op' | 'redir' | 'newline' | 'eof'
    text: str
    start: int
    end: int
    word: Optional[Word] = None
    redir: Optional[Redirect] = None


class _Parser:
    def __init__(self, src: str, depth: int = 0):
        if depth > _MAX_DEPTH:
            raise ParseError("nesting too deep")
        self.src = src
        self.pos = 0
        self.depth = depth
        self._peeked: Optional[_Tok] = None
        self._pending_heredocs: list[tuple[Redirect, str, bool]] = []

    # ---------------- character helpers ---------------- #
    def _ch(self, off: int = 0) -> str:
        i = self.pos + off
        return self.src[i] if i < len(self.src) else ""

    def _startswith(self, s: str) -> bool:
        return self.src.startswith(s, self.pos)

    def _skip_blanks(self) -> None:
        while True:
            c = self._ch()
            if c in (" ", "\t"):
                self.pos += 1
            elif c == "\\" and self._ch(1) == "\n":      # line continuation
                self.pos += 2
            elif c == "#" and self._at_word_start():     # comment to end of line
                while self._ch() not in ("", "\n"):
                    self.pos += 1
            else:
                return

    def _at_word_start(self) -> bool:
        return self.pos == 0 or self.src[self.pos - 1] in " \t\n;&|()"

    # ---------------- tokens ---------------- #
    def peek(self) -> _Tok:
        if self._peeked is None:
            self._peeked = self._lex()
        return self._peeked

    def next(self) -> _Tok:
        tok = self.peek()
        self._peeked = None
        return tok

    def _lex(self) -> _Tok:
        self._skip_blanks()
        start = self.pos
        c = self._ch()
        if c == "":
            if self._pending_heredocs:
                self._read_heredocs()
            return _Tok("eof", "", start, start)
        if c == "\n":
            self.pos += 1
            self._read_heredocs()
            return _Tok("newline", "\n", start, self.pos)

        # process substitution looks like a redirect but is a word
        if c in "<>" and self._ch(1) == "(":
            return self._lex_word(start)

        # fd-prefixed redirect: 2>file, 2>&1, 10<in
        j = self.pos
        while j < len(self.src) and self.src[j].isdigit():
            j += 1
        if j > self.pos and j < len(self.src) and self.src[j] in "<>" and not (
                j + 1 < len(self.src) and self.src[j + 1] == "("):
            fd = int(self.src[self.pos:j])
            self.pos = j
            return self._lex_redirect(start, fd)

        if c in "<>" or (c == "&" and self._ch(1) == ">"):
            return self._lex_redirect(start, None)

        for op in ("&&", "||", ";;&", ";;", ";&", "|&", "&", "|", ";", "(", ")"):
            if self._startswith(op):
                self.pos += len(op)
                return _Tok("op", op, start, self.pos)

        return self._lex_word(start)

    def _lex_redirect(self, start: int, fd: Optional[int]) -> _Tok:
        for op in _REDIR_OPS:
            if self._startswith(op):
                self.pos += len(op)
                break
        else:  # pragma: no cover - guarded by caller
            raise ParseError("bad redirect")
        if op in ("<<", "<<-"):
            self._skip_blanks()
            delim_tok = self._lex_word(self.pos)
            delim_word = delim_tok.word
            delim = "".join(p if isinstance(p, str) else "" for _, p in delim_word.parts)
            redir = Redirect(op=op, fd=fd, target=None, heredoc_quoted=delim_word.quoted)
            self._pending_heredocs.append((redir, delim, op == "<<-"))
            return _Tok("redir", op, start, self.pos, redir=redir)
        if op in (">&", "<&"):
            self._skip_blanks()
            # `>&2`, `>&-`, or `>& file` (bash: same as &>)
            m = self.pos
            while m < len(self.src) and (self.src[m].isdigit() or self.src[m] == "-"):
                m += 1
            if m > self.pos and (m >= len(self.src) or self.src[m] in _META):
                tgt = Word(raw=self.src[self.pos:m], parts=[("lit", self.src[self.pos:m])])
                self.pos = m
                return _Tok("redir", op, start, self.pos, redir=Redirect(op=op, fd=fd, target=tgt))
        self._skip_blanks()
        if self._ch() in ("", "\n") or (self._ch() in _META and not (self._ch() in "<>" and self._ch(1) == "(")):
            raise ParseError(f"redirect '{op}' has no target")
        tgt = self._lex_word(self.pos).word
        return _Tok("redir", op, start, self.pos, redir=Redirect(op=op, fd=fd, target=tgt))

    def _read_heredocs(self) -> None:
        for redir, delim, strip_tabs in self._pending_heredocs:
            lines = []
            while True:
                if self.pos >= len(self.src):
                    break  # unterminated heredoc: bash warns and uses EOF
                nl = self.src.find("\n", self.pos)
                line = self.src[self.pos:] if nl == -1 else self.src[self.pos:nl]
                self.pos = len(self.src) if nl == -1 else nl + 1
                check = line.lstrip("\t") if strip_tabs else line
                if check == delim:
                    break
                lines.append(check)
            body = "\n".join(lines) + ("\n" if lines else "")
            redir.heredoc = body
            if not redir.heredoc_quoted:
                redir.heredoc_subs = _subs_in_text(body, self.depth)
        self._pending_heredocs = []

    # ---------------- words ---------------- #
    def _lex_word(self, start: int) -> _Tok:
        parts: list = []
        quoted = False
        lit: list[str] = []

        def flush():
            if lit:
                parts.append(("lit", "".join(lit)))
                lit.clear()

        first = True
        while True:
            c = self._ch()
            if c == "":
                break
            if c in "<>" and self._ch(1) == "(":
                # process substitution <( .. ) / >( .. )
                flush()
                self.pos += 2
                sub = self._parse_nested(")")
                parts.append(("cmd", sub))
                first = False
                continue
            if c in _META:
                break
            if c == "\\":
                nxt = self._ch(1)
                if nxt == "\n":
                    self.pos += 2
                    continue
                if nxt == "":
                    self.pos += 1
                    break
                lit.append(nxt)
                quoted = True
                self.pos += 2
            elif c == "'":
                end = self.src.find("'", self.pos + 1)
                if end == -1:
                    raise ParseError("unterminated single quote")
                lit.append(self.src[self.pos + 1:end])
                quoted = True
                self.pos = end + 1
            elif c == "$" and self._ch(1) == "'":
                lit.append(self._read_ansi_c())
                quoted = True
            elif c == "$" and self._ch(1) == '"':
                self.pos += 1  # locale string -> treat as double quotes
                continue
            elif c == '"':
                flush()
                self.pos += 1
                self._read_double_quoted(parts)
                quoted = True
            elif c == "$":
                flush()
                parts.append(self._read_dollar())
            elif c == "`":
                flush()
                parts.append(("cmd", self._read_backtick()))
            elif c == "~" and first and not parts and not lit:
                # tilde prefix: ~, ~/x, ~user/x
                self.pos += 1
                user = []
                while self._ch() and self._ch() not in _META and self._ch() not in "/:'\"$`\\":
                    user.append(self._ch())
                    self.pos += 1
                parts.append(("tilde", "".join(user)))
            elif c in "*?":
                flush()
                parts.append(("glob", c))
                self.pos += 1
            elif c == "[" and self._looks_like_bracket_glob():
                flush()
                end = self.src.find("]", self.pos + 2)
                parts.append(("glob", self.src[self.pos:end + 1]))
                self.pos = end + 1
            elif c in "@+!" and self._ch(1) == "(":
                # extglob @(a|b) — keep as glob text
                flush()
                depth, i = 0, self.pos + 1
                while i < len(self.src):
                    if self.src[i] == "(":
                        depth += 1
                    elif self.src[i] == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    i += 1
                parts.append(("glob", self.src[self.pos:i + 1]))
                self.pos = i + 1
            else:
                lit.append(c)
                self.pos += 1
            first = False
        flush()
        if not parts and self.pos == start:
            raise ParseError(f"unexpected character {self._ch()!r} at {self.pos}")
        word = Word(raw=self.src[start:self.pos], parts=_merge_lits(parts), quoted=quoted)
        return _Tok("word", word.raw, start, self.pos, word=word)

    def _looks_like_bracket_glob(self) -> bool:
        end = self.src.find("]", self.pos + 2)
        if end == -1:
            return False
        inner = self.src[self.pos + 1:end]
        return bool(inner) and not any(ch in _META or ch in "'\"$" for ch in inner)

    def _read_ansi_c(self) -> str:
        self.pos += 2  # skip $'
        out = []
        while True:
            c = self._ch()
            if c == "":
                raise ParseError("unterminated $'...'")
            if c == "'":
                self.pos += 1
                return "".join(out)
            if c != "\\":
                out.append(c)
                self.pos += 1
                continue
            e = self._ch(1)
            self.pos += 2
            if e in _ANSI_C:
                out.append(_ANSI_C[e])
            elif e == "x":
                h = self._take_while(lambda ch: ch in "0123456789abcdefABCDEF", 2)
                out.append(chr(int(h, 16)) if h else "\\x")
            elif e in ("u", "U"):
                h = self._take_while(lambda ch: ch in "0123456789abcdefABCDEF", 4 if e == "u" else 8)
                try:
                    out.append(chr(int(h, 16)) if h else "\\" + e)
                except (ValueError, OverflowError):
                    out.append("�")
            elif e in "01234567":
                self.pos -= 1
                o = self._take_while(lambda ch: ch in "01234567", 3)
                out.append(chr(int(o, 8) & 0xFF))
            elif e == "c":
                ctl = self._ch()
                self.pos += 1
                out.append(chr(ord(ctl.upper()) ^ 0x40) if ctl else "")
            else:
                out.append("\\" + e)

    def _take_while(self, pred, limit: int) -> str:
        out = []
        while len(out) < limit and self._ch() and pred(self._ch()):
            out.append(self._ch())
            self.pos += 1
        return "".join(out)

    def _read_double_quoted(self, parts: list) -> None:
        lit: list[str] = []
        while True:
            c = self._ch()
            if c == "":
                raise ParseError("unterminated double quote")
            if c == '"':
                self.pos += 1
                break
            if c == "\\" and self._ch(1) in ('$', '`', '"', "\\", "\n"):
                if self._ch(1) != "\n":
                    lit.append(self._ch(1))
                self.pos += 2
            elif c == "$" and (self._ch(1).isalnum() or self._ch(1) in "_{(@*#?$!-"):
                if lit:
                    parts.append(("lit", "".join(lit)))
                    lit = []
                parts.append(self._read_dollar())
            elif c == "`":
                if lit:
                    parts.append(("lit", "".join(lit)))
                    lit = []
                parts.append(("cmd", self._read_backtick()))
            else:
                lit.append(c)
                self.pos += 1
        if lit:
            parts.append(("lit", "".join(lit)))

    def _read_dollar(self):
        # assumes self._ch() == '$'
        if self._startswith("$(("):
            self.pos += 3
            depth, i = 2, self.pos
            while i < len(self.src) and depth:
                if self.src[i] == "(":
                    depth += 1
                elif self.src[i] == ")":
                    depth -= 1
                i += 1
            if depth:
                raise ParseError("unterminated $((")
            text = self.src[self.pos:i - 2]
            self.pos = i
            return ("arith", text)
        if self._startswith("$("):
            self.pos += 2
            return ("cmd", self._parse_nested(")"))
        if self._startswith("${"):
            self.pos += 2
            depth, i = 1, self.pos
            while i < len(self.src):
                ch = self.src[i]
                if ch == "\\":
                    i += 2
                    continue
                if ch == "'":
                    j = self.src.find("'", i + 1)
                    i = (j if j != -1 else len(self.src) - 1) + 1
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            if depth:
                raise ParseError("unterminated ${")
            inner = self.src[self.pos:i]
            self.pos = i + 1
            m = _PARAM_NAME.match(inner)
            name = m.group(0) if m and m.group(0) else inner
            rest = inner[len(name):] if m and m.group(0) else ""
            nested = []
            if rest:
                # operators like :-, :=, :+, #, %, / may embed words with substitutions
                op_len = 2 if rest[:2] in (":-", ":=", ":+", ":?", "##", "%%", "//") else 1
                body = rest[op_len:]
                if body:
                    try:
                        sub = _Parser(body, self.depth + 1)
                        while sub.pos < len(body):
                            sub._skip_blanks()
                            if sub.pos >= len(body):
                                break
                            if body[sub.pos] in _META:
                                sub.pos += 1
                                continue
                            nested.append(sub._lex_word(sub.pos).word)
                    except ParseError:
                        pass
            return ("var", (name, nested))
        # $NAME, $1, $@, $?, ...
        self.pos += 1
        c = self._ch()
        if c and (c.isalpha() or c == "_"):
            start = self.pos
            while self._ch() and (self._ch().isalnum() or self._ch() == "_"):
                self.pos += 1
            return ("var", self.src[start:self.pos])
        if c and (c.isdigit() or c in "@*#?$!-"):
            self.pos += 1
            return ("var", c)
        return ("lit", "$")

    def _read_backtick(self):
        self.pos += 1
        out, i = [], self.pos
        while i < len(self.src):
            ch = self.src[i]
            if ch == "\\" and i + 1 < len(self.src) and self.src[i + 1] in "`$\\":
                out.append(self.src[i + 1])
                i += 2
                continue
            if ch == "`":
                break
            out.append(ch)
            i += 1
        else:
            raise ParseError("unterminated backtick")
        self.pos = i + 1
        return _Parser("".join(out), self.depth + 1).parse_script()

    def _parse_nested(self, closer: str) -> Script:
        """Parse a script that ends at an unmatched ``closer`` (used for $( ) and <( ))."""
        sub = _Parser(self.src, self.depth + 1)
        sub.pos = self.pos
        script = sub.parse_list(stop_ops={closer})
        tok = sub.next()
        if tok.kind != "op" or tok.text != closer:
            raise ParseError(f"expected '{closer}'")
        script.source = self.src[self.pos:tok.start]
        self.pos = tok.end
        return script

    # ---------------- grammar ---------------- #
    def parse_script(self) -> Script:
        script = self.parse_list(stop_ops=set())
        tok = self.peek()
        if tok.kind != "eof":
            raise ParseError(f"unexpected {tok.text!r} at {tok.start}")
        script.source = self.src
        return script

    def _is_kw(self, tok: _Tok, *kws: str) -> bool:
        return tok.kind == "word" and tok.word is not None and not tok.word.quoted and tok.text in kws

    def parse_list(self, stop_ops: set, stop_kws: tuple = ()) -> Script:
        items: list[AndOr] = []
        while True:
            tok = self.peek()
            while tok.kind == "newline" or (tok.kind == "op" and tok.text == ";"):
                self.next()
                tok = self.peek()
            if tok.kind == "eof":
                break
            if tok.kind == "op" and (tok.text in stop_ops or tok.text in (";;", ";&", ";;&")):
                break
            if stop_kws and self._is_kw(tok, *stop_kws):
                break
            if tok.kind == "op" and tok.text == ")":
                raise ParseError("unexpected ')'")
            andor = self.parse_and_or()
            sep = self.peek()
            if sep.kind == "op" and sep.text == "&":
                self.next()
                andor.background = True
            elif sep.kind == "op" and sep.text == ";":
                self.next()
            elif sep.kind == "newline":
                self.next()
            items.append(andor)
        return Script(items=items)

    def parse_and_or(self) -> AndOr:
        pipes = [self.parse_pipeline()]
        ops = []
        while True:
            tok = self.peek()
            if tok.kind == "op" and tok.text in ("&&", "||"):
                self.next()
                while self.peek().kind == "newline":
                    self.next()
                ops.append(tok.text)
                pipes.append(self.parse_pipeline())
            else:
                return AndOr(pipelines=pipes, ops=ops)

    def parse_pipeline(self) -> Pipeline:
        negated = False
        if self._is_kw(self.peek(), "!"):
            self.next()
            negated = True
        cmds = [self.parse_command()]
        while True:
            tok = self.peek()
            if tok.kind == "op" and tok.text in ("|", "|&"):
                self.next()
                while self.peek().kind == "newline":
                    self.next()
                cmds.append(self.parse_command())
            else:
                return Pipeline(commands=cmds, negated=negated)

    def parse_command(self) -> Command:
        tok = self.peek()
        if tok.kind == "eof":
            raise ParseError("expected a command")
        if tok.kind == "op" and tok.text == "(":
            if self.src.startswith("((", tok.start):
                self._peeked = None
                self.pos = tok.start + 2
                return self._read_arith(tok.start)
            self.next()
            body = self.parse_list(stop_ops={")"})
            close = self.next()
            if close.text != ")":
                raise ParseError("expected ')'")
            return Compound("subshell", [body], redirects=self._trailing_redirects(), start=tok.start, end=close.end)
        if tok.kind == "word" and not tok.word.quoted:
            t = tok.text
            if t == "{":
                self.next()
                body = self.parse_list(stop_ops=set(), stop_kws=("}",))
                self._expect_kw("}")
                return Compound("group", [body], redirects=self._trailing_redirects(), start=tok.start, end=self.pos)
            if t == "if":
                return self._parse_if()
            if t in ("while", "until"):
                self.next()
                cond = self.parse_list(stop_ops=set(), stop_kws=("do",))
                self._expect_kw("do")
                body = self.parse_list(stop_ops=set(), stop_kws=("done",))
                self._expect_kw("done")
                return Compound(t, [cond, body], redirects=self._trailing_redirects(), start=tok.start, end=self.pos)
            if t in ("for", "select"):
                return self._parse_for()
            if t == "case":
                return self._parse_case()
            if t == "[[":
                return self._parse_cond()
            if t == "function":
                self.next()
                name = self.next()
                if name.kind != "word":
                    raise ParseError("expected function name")
                if self.peek().kind == "op" and self.peek().text == "(":
                    self.next()
                    if self.next().text != ")":
                        raise ParseError("expected ')'")
                while self.peek().kind == "newline":
                    self.next()
                body = self.parse_command()
                return Compound("function", [_as_script(body)], name=name.text, start=tok.start, end=self.pos)
            if t in _RESERVED_ANY - _RESERVED_START:
                raise ParseError(f"unexpected keyword {t!r}")
        return self._parse_simple()

    def _read_arith(self, start: int) -> Compound:
        """Read ``(( .. ))``; ``self.pos`` must sit just after the opening ``((``."""
        depth, i = 0, self.pos
        while i < len(self.src):
            ch = self.src[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                if depth == 0:
                    if i + 1 < len(self.src) and self.src[i + 1] == ")":
                        break
                    raise ParseError("bad (( ))")
                depth -= 1
            i += 1
        else:
            raise ParseError("unterminated (( ))")
        text = self.src[self.pos:i]
        self.pos = i + 2
        w = Word(raw=text, parts=[("arith", text)])
        return Compound("arith", [], words=[w], start=start, end=self.pos)

    def _expect_kw(self, kw: str) -> None:
        tok = self.next()
        if not self._is_kw(tok, kw):
            raise ParseError(f"expected '{kw}', got {tok.text!r}")

    def _parse_if(self) -> Compound:
        start = self.next().start
        bodies = []
        cond = self.parse_list(stop_ops=set(), stop_kws=("then",))
        self._expect_kw("then")
        bodies += [cond, self.parse_list(stop_ops=set(), stop_kws=("elif", "else", "fi"))]
        while True:
            tok = self.next()
            if self._is_kw(tok, "elif"):
                c = self.parse_list(stop_ops=set(), stop_kws=("then",))
                self._expect_kw("then")
                bodies += [c, self.parse_list(stop_ops=set(), stop_kws=("elif", "else", "fi"))]
            elif self._is_kw(tok, "else"):
                bodies.append(self.parse_list(stop_ops=set(), stop_kws=("fi",)))
                self._expect_kw("fi")
                break
            elif self._is_kw(tok, "fi"):
                break
            else:
                raise ParseError("expected 'fi'")
        return Compound("if", bodies, redirects=self._trailing_redirects(), start=start, end=self.pos)

    def _parse_for(self) -> Compound:
        start = self.next().start
        if self.peek().kind == "op" and self.src.startswith("((", self.peek().start):
            # C-style for (( ; ; ))
            p0 = self.peek().start
            self._peeked = None
            self.pos = p0 + 2
            arith = self._read_arith(start)
            while self.peek().kind == "newline" or (self.peek().kind == "op" and self.peek().text == ";"):
                self.next()
            self._expect_kw("do")
            body = self.parse_list(stop_ops=set(), stop_kws=("done",))
            self._expect_kw("done")
            return Compound("for", [body], words=arith.words, name=None, start=start, end=self.pos)
        name = self.next()
        if name.kind != "word":
            raise ParseError("expected loop variable")
        items: list[Word] = []
        has_in = False
        while self.peek().kind == "newline":
            self.next()
        if self._is_kw(self.peek(), "in"):
            self.next()
            has_in = True
            while self.peek().kind == "word":
                if self._is_kw(self.peek(), "do"):
                    break
                items.append(self.next().word)
        while self.peek().kind == "newline" or (self.peek().kind == "op" and self.peek().text == ";"):
            self.next()
        if self._is_kw(self.peek(), "{"):
            self.next()
            body = self.parse_list(stop_ops=set(), stop_kws=("}",))
            self._expect_kw("}")
        else:
            self._expect_kw("do")
            body = self.parse_list(stop_ops=set(), stop_kws=("done",))
            self._expect_kw("done")
        if not has_in:
            items = [Word(raw='"$@"', parts=[("var", "@")], quoted=True)]
        return Compound("for", [body], words=items, name=name.text, redirects=self._trailing_redirects(),
                        start=start, end=self.pos)

    def _parse_case(self) -> Compound:
        start = self.next().start
        subject = self.next()
        if subject.kind != "word":
            raise ParseError("expected case subject")
        while self.peek().kind == "newline":
            self.next()
        self._expect_kw("in")
        bodies = []
        words = [subject.word]
        while True:
            while self.peek().kind == "newline":
                self.next()
            tok = self.peek()
            if self._is_kw(tok, "esac"):
                self.next()
                break
            if tok.kind == "eof":
                raise ParseError("unterminated case")
            if tok.kind == "op" and tok.text == "(":
                self.next()
            # patterns until ')'
            while True:
                p = self.next()
                if p.kind == "op" and p.text == ")":
                    break
                if p.kind == "op" and p.text == "|":
                    continue
                if p.kind != "word":
                    raise ParseError("bad case pattern")
                words.append(p.word)
            bodies.append(self.parse_list(stop_ops=set(), stop_kws=("esac",)))
            tok = self.peek()
            if tok.kind == "op" and tok.text in (";;", ";&", ";;&"):
                self.next()
        return Compound("case", bodies, words=words, redirects=self._trailing_redirects(), start=start, end=self.pos)

    def _parse_cond(self) -> Compound:
        start = self.next().start
        words = []
        while True:
            tok = self.peek()
            if tok.kind == "eof":
                raise ParseError("unterminated [[")
            if self._is_kw(tok, "]]"):
                self.next()
                break
            self.next()
            if tok.kind == "word":
                words.append(tok.word)
            # operators like && || ( ) < > inside [[ ]] are fine to skip
        return Compound("cond", [], words=words, start=start, end=self.pos)

    def _trailing_redirects(self) -> list:
        out = []
        while self.peek().kind == "redir":
            out.append(self.next().redir)
        return out

    def _parse_simple(self) -> Command:
        start = self.peek().start
        assignments, words, redirects = [], [], []
        while True:
            tok = self.peek()
            if tok.kind == "redir":
                self.next()
                redirects.append(tok.redir)
                continue
            if tok.kind != "word":
                break
            # a reserved word ends a simple command only in command position
            if not words and not assignments and self._is_kw(tok, *(_RESERVED_ANY - {"{", "[[", "!"})):
                break
            self.next()
            w = tok.word
            if not words and _is_assignment(w):
                name, val = _split_assignment(w)
                # array assignment X=( a b )
                if val.raw == "" and self.peek().kind == "op" and self.peek().text == "(" \
                        and tok.end == self.peek().start:
                    self.next()
                    arr = []
                    while not (self.peek().kind == "op" and self.peek().text == ")"):
                        t = self.next()
                        if t.kind == "eof":
                            raise ParseError("unterminated array")
                        if t.kind == "word":
                            arr.append(t.word)
                    self.next()
                    val = Word(raw="(" + " ".join(a.raw for a in arr) + ")",
                               parts=[p for a in arr for p in a.parts + [("lit", " ")]][:-1] or [("lit", "")])
                assignments.append((name, val))
                continue
            # function definition: name() { ...; }
            if not words and not assignments and w.is_static and self.peek().kind == "op" \
                    and self.peek().text == "(":
                save_pos, save_peek = self.pos, self._peeked
                self.next()
                if self.peek().kind == "op" and self.peek().text == ")":
                    self.next()
                    while self.peek().kind == "newline":
                        self.next()
                    body = self.parse_command()
                    return Compound("function", [_as_script(body)], name=w.value, start=start, end=self.pos)
                self.pos, self._peeked = save_pos, save_peek
            words.append(w)
        if not words and not assignments and not redirects:
            tok = self.peek()
            raise ParseError(f"unexpected {tok.text!r} at {tok.start}")
        return SimpleCommand(assignments, words, redirects, start=start, end=self.pos)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _merge_lits(parts: list) -> list:
    out: list = []
    for kind, payload in parts:
        if kind == "lit" and out and out[-1][0] == "lit":
            out[-1] = ("lit", out[-1][1] + payload)
        else:
            out.append((kind, payload))
    return out


def _is_assignment(w: Word) -> bool:
    if not w.parts or w.parts[0][0] != "lit":
        return False
    head = w.parts[0][1]
    eq = head.find("=")
    if eq <= 0:
        return False
    name = head[:eq].rstrip("+")
    if "[" in name:
        name = name[:name.index("[")]
    return name.replace("_", "a").isalnum() and not name[0].isdigit() and not w.raw.startswith(("'", '"'))


def _split_assignment(w: Word) -> tuple[str, Word]:
    head = w.parts[0][1]
    eq = head.find("=")
    name = head[:eq].rstrip("+")
    rest_lit = head[eq + 1:]
    parts = ([("lit", rest_lit)] if rest_lit else []) + list(w.parts[1:])
    raw = w.raw[w.raw.find("=") + 1:]
    return name, Word(raw=raw, parts=parts or [("lit", "")], quoted=w.quoted)


def _as_script(cmd: Command) -> Script:
    return Script(items=[AndOr(pipelines=[Pipeline(commands=[cmd])], ops=[])])


def _subs_in_text(text: str, depth: int) -> list:
    """Find $( .. ) and backtick substitutions in heredoc bodies."""
    subs = []
    p = _Parser(text, depth + 1)
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "$" and text.startswith("$(", i) and not text.startswith("$((", i):
            p.pos = i
            try:
                kind, payload = p._read_dollar()
                subs.append(payload)
                i = p.pos
                continue
            except ParseError:
                pass
        elif ch == "`":
            p.pos = i
            try:
                subs.append(p._read_backtick())
                i = p.pos
                continue
            except ParseError:
                pass
        i += 1
    return subs


def parse(src: str) -> Script:
    """Parse a bash command line. Raises :class:`ParseError` on malformed input."""
    if "\x00" in src:
        raise ParseError("NUL byte in command")
    return _Parser(src).parse_script()
