"""Where does a path point, relative to the agent's project?

Paths are mapped into a small virtual filesystem so that ``cd`` and ``..`` can be
followed without touching the real disk:

    /__out__/__proj__     the project root (agent's starting directory)
    /__out__              everything outside the project we can't name
    /__home__             the user's home directory
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Optional

PROJECT = "/__out__/__proj__"
OUTSIDE = "/__out__"
HOME = "/__home__"

NULL_DEVICES = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty", "/dev/zero",
                "/dev/random", "/dev/urandom"}
TMP_PREFIXES = ("/tmp", "/var/tmp", "/private/tmp", "/private/var/folders", "/var/folders", "/dev/shm")
SYSTEM_PREFIXES = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/opt", "/var", "/boot",
                   "/sys", "/proc", "/srv", "/System", "/Library", "/Applications", "/private/etc",
                   "/private/var", "/snap", "/root", "/nix", "/run", "/mnt", "/media", "/Volumes")

# files whose contents are credentials: printing them puts secrets in the agent transcript
_SECRET_PATTERNS = [
    r"(^|/)\.env(\.[\w.-]+)?$", r"(^|/)\.ssh(/|$)", r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$",
    r"\.pem$", r"\.key$", r"\.p12$", r"\.pfx$", r"(^|/)\.aws(/|$)", r"(^|/)\.netrc$", r"(^|/)\.npmrc$",
    r"(^|/)\.pypirc$", r"(^|/)\.git-credentials$", r"(^|/)\.kube/config$", r"(^|/)\.docker/config\.json$",
    r"(^|/)\.config/gh/hosts\.yml$", r"(^|/)\.config/gcloud(/|$)", r"(^|/)credentials(\.json)?$",
    r"(^|/)secrets?(\.(json|ya?ml|toml))?$", r"(^|/)\.vault-token$", r"(^|/)shadow$", r"(^|/)\.gnupg(/|$)",
    r"(^|/)service[-_]account.*\.json$", r"(^|/)\.terraformrc$", r"(^|/)terraform\.tfstate$",
]
_SECRET_RE = re.compile("|".join(_SECRET_PATTERNS))
_PUBLIC_KEY_RE = re.compile(r"\.pub$")

# files that run automatically later (shell start-up, scheduled jobs, git hooks)
_AUTORUN_RE = re.compile(
    r"(^|/)\.(bashrc|bash_profile|profile|zshrc|zprofile|zshenv|bash_login|bash_logout|config/fish/config\.fish)$"
    r"|(^|/)\.git/hooks/|(^|/)Library/LaunchAgents/|(^|/)\.config/autostart/|(^|/)\.ssh/authorized_keys$")


@dataclass(frozen=True)
class Target:
    """A resolved path target."""

    shown: str            # what to show the user
    vpath: Optional[str]  # virtual absolute path (None when unknowable)
    scope: str            # see SCOPES below
    broad: bool = False   # glob that matches everything in a directory (`*`, `.*`)
    secret: bool = False
    autorun: bool = False
    is_git_dir: bool = False


SCOPES = ("null", "tmp", "project", "project_root", "outside", "home", "home_root", "system", "root",
          "device", "remote", "unknown", "unknown_root")


def to_virtual(path: str, cwd: Optional[str], project_root: Optional[str], home: Optional[str]) -> Optional[str]:
    """Map a path (already with ``~``/``$HOME`` substituted) into the virtual filesystem."""
    if project_root and (path == project_root or path.startswith(project_root.rstrip("/") + "/")):
        path = PROJECT + path[len(project_root.rstrip("/")):]
    elif home and (path == home or path.startswith(home.rstrip("/") + "/")):
        path = HOME + path[len(home.rstrip("/")):]
    if not path.startswith("/"):
        if cwd is None:
            return None
        path = posixpath.join(cwd, path)
    return posixpath.normpath(path) if path != "//" else "/"


def classify(shown: str, vpath: Optional[str], broad: bool = False) -> Target:
    secret = bool(_SECRET_RE.search(shown)) and not _PUBLIC_KEY_RE.search(shown)
    autorun = bool(_AUTORUN_RE.search(shown))
    if vpath is None:
        return Target(shown, None, "unknown", broad, secret, autorun)
    is_git = vpath == PROJECT + "/.git"
    if vpath == PROJECT:
        scope = "project_root"
    elif vpath.startswith(PROJECT + "/"):
        scope = "project"
    elif vpath == OUTSIDE or vpath.startswith(OUTSIDE + "/"):
        scope = "outside"
    elif vpath == HOME:
        scope = "home_root"
    elif vpath.startswith(HOME + "/"):
        scope = "home"
    elif vpath == "/":
        scope = "root"
    elif vpath in NULL_DEVICES or vpath.startswith("/dev/fd/"):
        scope = "null"
    elif vpath.startswith("/dev/"):
        scope = "device"
    elif any(vpath == p or vpath.startswith(p + "/") for p in TMP_PREFIXES):
        scope = "tmp"
    elif any(vpath == p or vpath.startswith(p + "/") for p in SYSTEM_PREFIXES):
        scope = "system"
    elif re.match(r"^/(Users|home)/[^/]+$", vpath):
        scope = "home_root"
    else:
        scope = "outside"
    return Target(shown, vpath, scope, broad, secret, autorun, is_git)


_BROAD_GLOBS = {"*", ".*", "*.*", "{.,}*", ".[!.]*", "..?*", "**", "*/", ".??*"}


def split_glob(path: str) -> tuple[str, bool, bool]:
    """Return (static directory part, has_glob, broad) for a glob path like ``src/*.py``.

    Only ``* ? [`` are treated as filename-matching globs. Brace expansion (``{a,b}``,
    or template placeholders like ``{{name}}``) does not match existing files, so it is
    left as a literal path component.
    """
    if not any(ch in path for ch in "*?["):
        return path, False, False
    comps = path.split("/")
    for i, comp in enumerate(comps):
        if any(ch in comp for ch in "*?["):
            base = "/".join(comps[:i]) or ("/" if path.startswith("/") else ".")
            rest = "/".join(comps[i:]).rstrip("/")
            broad = rest in _BROAD_GLOBS or rest.startswith("**")
            return base, True, broad
    return path, False, False  # pragma: no cover
