"""Parser tests: quoting, expansion, substitution, heredocs, compound structures."""
import pytest

from blast_radius.shell import parse, ParseError, SimpleCommand, Compound


def commands(script):
    """Flatten a parsed script into simple commands (recursing into compounds/subs)."""
    out = []

    def walk(s):
        for ao in s.items:
            for pl in ao.pipelines:
                for c in pl.commands:
                    if isinstance(c, SimpleCommand):
                        out.append(c)
                        for w in c.words:
                            for sub in w.subs:
                                walk(sub)
                        for r in c.redirects:
                            for sub in r.heredoc_subs:
                                walk(sub)
                    else:
                        for b in c.bodies:
                            walk(b)
                        for w in c.words:
                            for sub in w.subs:
                                walk(sub)
    walk(script)
    return out


def first_values(script):
    return [c.words[0].value for c in commands(script) if c.words]


def test_plain():
    s = parse("ls -la /tmp")
    c = commands(s)[0]
    assert c.words[0].value == "ls"
    assert [w.value for w in c.words] == ["ls", "-la", "/tmp"]


def test_quote_removal_reveals_program():
    # quotes that obscure the program name are seen through
    assert first_values(parse("r''m -rf x")) == ["rm"]
    assert first_values(parse('"rm" -rf x')) == ["rm"]
    assert first_values(parse("r\\m -rf x")) == ["rm"]


def test_ansi_c_hex_decodes():
    # $'\x72\x6d' == "rm"
    assert first_values(parse(r"$'\x72\x6d' -rf x")) == ["rm"]


def test_single_quote_is_literal():
    c = commands(parse("echo '$HOME `id`'"))[0]
    assert c.words[1].value == "$HOME `id`"
    assert c.words[1].is_static


def test_double_quote_keeps_expansions():
    c = commands(parse('echo "hi $USER"'))[0]
    assert not c.words[1].is_static  # contains $USER


def test_command_substitution_is_recovered():
    vals = first_values(parse('echo "$(whoami)"'))
    assert "whoami" in vals


def test_backtick_substitution():
    vals = first_values(parse("echo `id`"))
    assert "id" in vals


def test_pipeline_splits_commands():
    s = parse("cat f | grep x | wc -l")
    assert first_values(s) == ["cat", "grep", "wc"]


def test_and_or_and_semicolons():
    s = parse("a && b || c ; d")
    assert first_values(s) == ["a", "b", "c", "d"]


def test_heredoc_body_and_delimiter():
    s = parse("cat <<EOF\nhello $(id)\nEOF\necho done")
    cmds = commands(s)
    assert cmds[0].words[0].value == "cat"
    r = cmds[0].redirects[0]
    assert r.op == "<<"
    assert "hello" in r.heredoc
    assert any(sub for sub in r.heredoc_subs)  # $(id) picked up


def test_quoted_heredoc_has_no_expansion():
    s = parse("cat <<'EOF'\n$(id)\nEOF")
    r = commands(s)[0].redirects[0]
    assert r.heredoc_quoted
    assert r.heredoc_subs == []


def test_redirect_targets():
    c = commands(parse("echo hi > out.txt 2>&1"))[0]
    ops = [r.op for r in c.redirects]
    assert ">" in ops


def test_for_loop_body():
    s = parse('for f in *.txt; do mv "$f" "${f%.txt}.md"; done')
    assert "mv" in first_values(s)


def test_if_statement():
    s = parse("if [ -f x ]; then cat x; else echo no; fi")
    vals = first_values(s)
    assert "cat" in vals and "echo" in vals


def test_case_statement():
    s = parse("case $1 in start) run;; stop|halt) halt;; esac")
    assert "run" in first_values(s)


def test_function_definition():
    s = parse("f() { rm -rf x; }; f")
    # body present as a compound function
    kinds = []

    def walk(sc):
        for ao in sc.items:
            for pl in ao.pipelines:
                for c in pl.commands:
                    if isinstance(c, Compound):
                        kinds.append(c.kind)
    walk(s)
    assert "function" in kinds


def test_arithmetic_command():
    s = parse("(( i++ ))")
    # should parse without error and not be a simple command
    assert s.items


def test_cstyle_for():
    s = parse("for ((i=0;i<3;i++)); do echo $i; done")
    assert "echo" in first_values(s)


def test_process_substitution():
    vals = first_values(parse("diff <(ls a) <(ls b)"))
    assert vals.count("ls") == 2


def test_nested_substitution():
    vals = first_values(parse('echo "$(echo $(id))"'))
    assert "id" in vals


def test_param_expansion_default_runs_command():
    vals = first_values(parse("echo ${X:-$(id)}"))
    assert "id" in vals


@pytest.mark.parametrize("bad", ["echo 'unterminated", 'echo "unterminated', "echo $(", "cat ${"])
def test_malformed_raises(bad):
    with pytest.raises(ParseError):
        parse(bad)


def test_nul_byte_rejected():
    with pytest.raises(ParseError):
        parse("echo \x00")


def test_comment_stripped():
    assert first_values(parse("git log # a comment")) == ["git"]


def test_line_continuation():
    assert first_values(parse("ls \\\n -la")) == ["ls"]


def test_deeply_nested_does_not_crash():
    parse("$(" * 30 + "id" + ")" * 30)
