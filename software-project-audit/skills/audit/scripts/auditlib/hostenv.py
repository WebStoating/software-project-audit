"""Environment and working-tree helpers for running the project's tests on the developer's machine."""
from __future__ import annotations

import os
from pathlib import Path

from .discover import EXCLUDED_DIRS

# The audited project may be third-party code: never hand it the developer's or the agent's credentials.
CREDENTIAL_PREFIXES = ("ANTHROPIC_", "OPENAI_", "CLAUDE_", "CODEX_", "AWS_", "AZURE_", "CLOUDSDK_")
CREDENTIAL_NAMES = frozenset({"GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS",
                              "SSH_AUTH_SOCK", "NPM_TOKEN", "NODE_AUTH_TOKEN", "PYPI_TOKEN"})
_PREPENDED = ("PATH", "PYTHONPATH")


def _is_credential(name: str) -> bool:
    return name in CREDENTIAL_NAMES or name.startswith(CREDENTIAL_PREFIXES)


def build_env(base, bin_dirs: list, extra: dict) -> tuple:
    """Return (env, stripped names): base minus credentials, plus extra; PATH/PYTHONPATH are prepended."""
    env = {k: v for k, v in base.items() if not _is_credential(k)}
    stripped = sorted(k for k in base if _is_credential(k))
    for key, value in extra.items():
        if key in _PREPENDED and env.get(key):
            env[key] = value + os.pathsep + env[key]
        else:
            env[key] = value
    if bin_dirs:
        env["PATH"] = os.pathsep.join(list(bin_dirs) + ([env["PATH"]] if env.get("PATH") else []))
    return env, stripped


def snapshot(project: Path) -> dict:
    """Map each project path (posix, relative) to (size, mtime_ns), skipping audit/ and dependency dirs."""
    root = str(project)
    out = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel = os.path.relpath(dirpath, root)
        # only the top-level audit/ is ours; src/audit/ is project code
        dirnames[:] = sorted(d for d in dirnames
                             if d not in EXCLUDED_DIRS or (d == "audit" and rel != "."))
        for name in sorted(filenames) + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]:
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            key = name if rel == "." else Path(rel, name).as_posix()
            out[key] = (st.st_size, st.st_mtime_ns)
    return out


def changed_paths(before: dict, after: dict) -> list:
    return sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))


def redact(text: str, project, home: str) -> str:
    """Show the project root as <project> and the home directory as ~ (project first: it may be under home)."""
    text = text.replace(str(project), "<project>")
    return text.replace(home, "~") if home else text
