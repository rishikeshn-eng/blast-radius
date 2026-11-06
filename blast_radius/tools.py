"""Knowledge base: how common command-line tools touch the filesystem, the network,
and the process table. Each entry tells the analyser how to turn a tool's argument
list into a set of effects on specific path targets.

This is deliberately declarative. ``analyze.py`` reads these specs; it does not special-case
tools in code. Unknown tools fall back to a conservative default.
"""

from __future__ import annotations

# Effect verbs the analyser understands.
# read  write  create  delete  move  chmod  chown  network  download  exec_dynamic
# shell_spawn  privilege  env_read  kill  mount  package  container  overwrite_inplace

# ---- option shapes ---------------------------------------------------------- #
# For each tool we record how to split flags from positional file operands, plus
# which effect the operands receive. Flags that TAKE a value are listed so the
# value isn't mistaken for a file.

GNU = "gnu"   # -x, --long, bundled -rf, -- terminator

# A spec is a dict with keys:
#   effects:        default effect(s) applied to each path operand
#   takes_value:    flags consuming the next token
#   value_flags:    --flag=... forms are auto-handled; these are space-separated ones
#   path_effect_flags: {flag: effect} flags that CHANGE the effect of operands
#   network:        True if the tool talks to the network
#   recursive_flags: flags that make an operation recursive (raises breadth)
#   force_flags:    flags that suppress prompts / ignore errors
#   no_clobber_flags: flags that make writes safe (won't overwrite)
#   operand_role:   'last_is_dest' (cp/mv), 'all', 'first', 'none'
#   reads_operands: effect applied to non-destination operands (cp/mv read sources)
#   runs_arg:       index/flag whose value is itself a command (sh -c, find -exec)

SPECS: dict[str, dict] = {}


def spec(*names, **kw):
    for n in names:
        SPECS[n] = kw


# ---- destructive / filesystem-mutating ------------------------------------- #
spec("rm", "unlink", effects=["delete"], recursive_flags={"-r", "-R", "--recursive"},
     force_flags={"-f", "--force"}, takes_value=set(), operand_role="all")
spec("rmdir", effects=["delete"], operand_role="all")
spec("shred", effects=["delete"], force_flags={"-f"}, operand_role="all")
spec("mv", effects=["move"], reads_operands="delete", operand_role="last_is_dest",
     dest_effect="create", takes_value={"-t", "--target-directory"},
     dest_flags={"-t": True, "--target-directory": True})
spec("cp", "install", effects=["create"], reads_operands="read", operand_role="last_is_dest",
     dest_effect="create", recursive_flags={"-r", "-R", "--recursive", "-a", "--archive"},
     takes_value={"-t", "--target-directory", "--suffix", "-S"}, force_flags={"-f"})
spec("dd", effects=["write"], network=False, operand_role="none", dd=True)
spec("truncate", effects=["write"], takes_value={"-s", "--size", "-r", "--reference"}, operand_role="all")
spec("mkdir", effects=["create"], takes_value={"-m", "--mode"}, operand_role="all")
spec("touch", effects=["create"], takes_value={"-d", "--date", "-r", "--reference", "-t"}, operand_role="all")
spec("ln", effects=["create"], operand_role="last_is_dest", dest_effect="create", reads_operands="read")
spec("tee", effects=["write"], force_flags={"-a", "--append"}, operand_role="all")
spec("chmod", effects=["chmod"], recursive_flags={"-R", "--recursive"}, operand_role="all", skip_first_operand=True)
spec("chown", "chgrp", effects=["chown"], recursive_flags={"-R", "--recursive"}, operand_role="all",
     skip_first_operand=True)
spec("mkfs", "mkfs.ext4", "mkfs.ext3", "mkfs.xfs", "mkfs.btrfs", "mke2fs", effects=["write"],
     operand_role="all", device_op=True)
spec("mount", "umount", effects=["mount"], operand_role="all", privileged=True)
spec("fdisk", "parted", "sgdisk", "wipefs", "blkdiscard", effects=["write"], operand_role="all", device_op=True)

# ---- read-only ------------------------------------------------------------- #
for ro in ["cat", "less", "more", "head", "tail", "bat", "nl", "od", "xxd", "hexdump", "strings",
           "file", "stat", "wc", "md5sum", "sha1sum", "sha256sum", "cksum", "readlink", "realpath",
           "basename", "dirname", "du", "df", "tree", "column", "fold", "rev", "tac", "cut", "paste",
           "sort", "uniq", "join", "comm", "diff", "cmp", "look", "pr", "fmt", "csplit"]:
    spec(ro, effects=["read"], operand_role="all", takes_value={"-n", "-c", "--lines", "--bytes"})
spec("ls", "dir", "vdir", "lsof", effects=["read"], operand_role="all")
spec("find", effects=["read"], operand_role="all", find=True)
spec("grep", "egrep", "fgrep", "rg", "ag", "ack", effects=["read"], operand_role="all",
     takes_value={"-e", "--regexp", "-f", "--file", "-m", "--max-count", "-A", "-B", "-C",
                  "--include", "--exclude", "--exclude-dir", "-g"}, skip_first_operand=True)
spec("pwd", "whoami", "id", "hostname", "uname", "date", "uptime", "env", "printenv", "set",
     "echo", "printf", "true", "false", "test", "seq", "yes", "which", "type", "command", "sleep",
     "clear", "tput", "locale", "groups", "tty", "logname", effects=[], operand_role="none")

# ---- editors / in-place mutation ------------------------------------------- #
spec("sed", effects=["read"], inplace_flags={"-i", "--in-place"}, inplace_effect="overwrite_inplace",
     takes_value={"-e", "--expression", "-f", "--file"}, skip_first_operand=True, operand_role="all")
spec("awk", "gawk", "mawk", effects=["read"], takes_value={"-f", "-v", "-F"}, skip_first_operand=True,
     operand_role="all")
spec("perl", effects=["exec_dynamic"], inplace_flags={"-i"}, inplace_effect="overwrite_inplace",
     takes_value={"-e", "-E", "-M"}, interp=True)
spec("tr", effects=["read"], operand_role="none")
spec("patch", effects=["overwrite_inplace"], takes_value={"-i", "--input", "-p", "--strip", "-d"},
     operand_role="all")

# ---- archives -------------------------------------------------------------- #
spec("tar", effects=["read"], tar=True, takes_value={"-f", "--file", "-C", "--directory",
     "--xform", "--transform", "-T", "--files-from"})
spec("zip", effects=["create"], operand_role="first", takes_value={})
spec("unzip", effects=["create"], takes_value={"-d"}, operand_role="first", extract=True)
spec("gunzip", "bunzip2", "unxz", effects=["overwrite_inplace"], operand_role="all")
spec("gzip", "bzip2", "xz", effects=["overwrite_inplace"], operand_role="all")
spec("7z", "7za", effects=["read"], operand_role="all", extract=True)

# ---- network / download ---------------------------------------------------- #
spec("curl", effects=["network"], network=True, download=True,
     takes_value={"-o", "--output", "-O", "-d", "--data", "-H", "--header", "-X", "--request",
                  "-u", "--user", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie",
                  "--data-binary", "--data-raw", "-F", "--form", "-T", "--upload-file"},
     output_flags={"-o", "--output"})
spec("wget", effects=["network"], network=True, download=True,
     takes_value={"-O", "--output-document", "-P", "--directory-prefix", "--post-data",
                  "--header", "-U", "--user-agent"}, output_flags={"-O", "--output-document"})
spec("nc", "ncat", "netcat", "socat", effects=["network"], network=True, operand_role="none")
spec("ssh", "scp", "sftp", "rsync", "telnet", "ftp", effects=["network"], network=True,
     takes_value={"-i", "-p", "-P", "-o", "-l", "-e"})
spec("ping", "dig", "nslookup", "host", "traceroute", "whois", "arp", "ifconfig", "ip",
     effects=["network"], network=True, operand_role="none")
spec("http", "https", "httpie", effects=["network"], network=True)

# ---- interpreters / dynamic execution -------------------------------------- #
spec("sh", "bash", "dash", "zsh", "ksh", "fish", effects=["shell_spawn"], interp=True,
     runs_flag="-c", takes_value={"-c", "-O", "-o"}, dash_stdin=True)
spec("python", "python2", "python3", "python3.11", "python3.12", "pypy", effects=["exec_dynamic"],
     interp=True, runs_flag="-c", takes_value={"-c", "-m", "-W", "-X"}, dash_stdin=True)
spec("node", "nodejs", "deno", "bun", effects=["exec_dynamic"], interp=True, runs_flag="-e",
     takes_value={"-e", "--eval", "-p", "--print"}, dash_stdin=True)
spec("ruby", effects=["exec_dynamic"], interp=True, runs_flag="-e", takes_value={"-e", "-r"})
spec("php", effects=["exec_dynamic"], interp=True, runs_flag="-r", takes_value={"-r", "-d"})
spec("eval", "source", ".", effects=["exec_dynamic"], eval_builtin=True)
spec("exec", effects=["shell_spawn"], exec_builtin=True)
spec("xargs", effects=["exec_dynamic"], runs_rest=True, takes_value={"-I", "-n", "-P", "-d", "-a", "-E"},
     skip_first_operand=False)
spec("env", effects=[], runs_rest=True, env_prefix=True)       # overridden: env CMD runs CMD
spec("nohup", "setsid", "timeout", "nice", "ionice", "stdbuf", "time", "watch", "chrt",
     effects=[], runs_rest=True, takes_value={"-s", "--signal", "-k"})
spec("make", effects=["exec_dynamic"], takes_value={"-f", "-C", "-j"}, build=True)
spec("sudo", "doas", effects=["privilege"], runs_rest=True, privileged=True,
     takes_value={"-u", "--user", "-g", "--group", "-p"}, flag_only={"-i", "-s", "-H", "-E", "-k"})
spec("su", effects=["privilege"], runs_rest=False, privileged=True)

# ---- package / system managers --------------------------------------------- #
spec("pip", "pip3", effects=["package", "network"], network=True, package=True,
     takes_value={"-r", "--requirement", "-i", "--index-url", "--extra-index-url"})
spec("npm", "pnpm", "yarn", "bun", effects=["package", "network"], network=True, package=True)
spec("npx", effects=["package", "network", "exec_dynamic"], network=True, runs_rest=True)
spec("gem", "cargo", "go", "apt", "apt-get", "yum", "dnf", "brew", "pacman", "apk", "conda",
     effects=["package", "network"], network=True, package=True, privileged=False)
spec("systemctl", "service", "launchctl", effects=["privilege"], operand_role="none")
spec("docker", "podman", "kubectl", effects=["container", "network"], network=True, operand_role="none")
spec("git", effects=["read"], git=True, takes_value={"-C", "-c", "--git-dir", "--work-tree"})
spec("kill", "pkill", "killall", effects=["kill"], operand_role="none")
spec("crontab", effects=["write"], takes_value={"-u"}, autorun=True)
spec("history", effects=["read"], operand_role="none")
spec("export", "unset", "alias", "local", "declare", "readonly", "typeset", effects=["env_read"],
     operand_role="none")
spec("cd", "pushd", "popd", "dirs", effects=[], cd=True, operand_role="none")


DEFAULT_SPEC = dict(effects=["read"], operand_role="all", unknown=True)


def lookup(name: str) -> dict:
    """Spec for a command name (basename, lower-cased for well-known tools)."""
    if name in SPECS:
        return SPECS[name]
    base = name.rsplit("/", 1)[-1]
    if base in SPECS:
        return SPECS[base]
    return DEFAULT_SPEC


# Commands that are pure builtins / have no filesystem reach even when unknown.
HARMLESS_BUILTINS = {"echo", "printf", "true", "false", "test", "[", ":", "pwd", "cd", "return",
                     "break", "continue", "shift", "wait", "times", "umask", "read", "let", "trap"}

# Common dev/test tools we don't model in detail but trust to read their args; suppresses
# the "unknown tool" note for the long tail of CLIs an agent runs constantly.
COMMON_DEV_TOOLS = {
    "pytest", "tox", "nox", "mypy", "ruff", "flake8", "black", "isort", "pylint", "pyright",
    "jest", "vitest", "mocha", "eslint", "prettier", "tsc", "tsx", "ts-node", "webpack", "vite",
    "rollup", "esbuild", "gradle", "mvn", "rustc", "clang", "gcc", "g++", "cmake", "ninja", "bazel",
    "ctest", "rspec", "rubocop", "phpunit", "composer", "dotnet", "javac", "kotlinc", "swift",
    "cargo-test", "gofmt", "golint", "staticcheck", "terraform", "ansible", "helm", "jq", "yq",
    "pandoc", "ffmpeg", "convert", "magick", "sqlite3", "psql", "mysql", "redis-cli", "aws", "gcloud",
    "az", "poetry", "pipenv", "uv", "hatch", "pre-commit", "mkdocs", "sphinx-build", "jupyter",
    "pip-compile", "twine", "wheel", "setup.py", "manage.py", "flask", "django-admin", "uvicorn",
    "gunicorn", "celery", "alembic", "prisma", "drizzle-kit", "turbo", "nx", "lerna", "deno",
}
