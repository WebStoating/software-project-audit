"""Host and sandbox readiness check: can an audit run here, and if not, how to fix it."""
from __future__ import annotations

import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from . import discover
from .dockerutil import SCANNER_IMAGE

PROBE_URL = "https://api.osv.dev/v1/query"
PROBE_TIMEOUT = 5
IMAGE_BUILD_MINUTES = 5
MIN_PYTHON = (3, 9)
SUPPORTED_STACKS = ("python", "javascript")

FIX_INSTALL_DOCKER = "Install Docker Desktop: https://docs.docker.com/get-docker/"
FIX_START_DAEMON = "Start Docker Desktop and rerun"
FIX_SANDBOX = ("Allow network access / Docker for this session (Codex: run with a sandbox mode "
               "that permits network and the Docker socket)")


def _check(name, ok, blocking, detail, fix=""):
    return {"name": name, "ok": bool(ok), "blocking": blocking, "detail": detail,
            "fix": "" if ok else fix}


def _docker(runner, docker, *args):
    """Return (ok, output); never raises."""
    try:
        r = runner([docker, *args], capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        return False, "docker executable not found: %s" % docker
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    return r.returncode == 0, out


def _looks_sandboxed(output: str) -> bool:
    low = output.lower()
    return "permission denied" in low or "operation not permitted" in low


def _probe(url: str):
    req = urllib.request.Request(url, data=b"{}", method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT):
            return True, "reached %s" % url
    except urllib.error.HTTPError as exc:
        return True, "reached %s (HTTP %d)" % (url, exc.code)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, "cannot reach %s: %s" % (url, getattr(exc, "reason", exc))


def check_readiness(project: Path, *, docker: str = "docker", probe_url: str = PROBE_URL,
                    runner=subprocess.run) -> dict:
    checks = []
    py = sys.version_info
    checks.append(_check("python", py[:2] >= MIN_PYTHON, True,
                         "Python %d.%d.%d" % py[:3],
                         "Install Python %d.%d or newer and rerun" % MIN_PYTHON))

    cli_ok, cli_out = _docker(runner, docker, "--version")
    checks.append(_check("docker_cli", cli_ok, True,
                         cli_out.splitlines()[0] if cli_out else "docker --version failed",
                         FIX_INSTALL_DOCKER))

    if cli_ok:
        d_ok, d_out = _docker(runner, docker, "info")
        fix = FIX_SANDBOX if _looks_sandboxed(d_out) else FIX_START_DAEMON
        detail = "Docker daemon reachable" if d_ok else (d_out.splitlines()[-1] if d_out else "docker info failed")
    else:
        d_ok, fix, detail = False, FIX_INSTALL_DOCKER, "Docker CLI unavailable"
    checks.append(_check("docker_daemon", d_ok, True, detail, fix))

    n_ok, n_detail = _probe(probe_url)
    checks.append(_check("network", n_ok, True, n_detail, FIX_SANDBOX))

    tag = SCANNER_IMAGE
    if d_ok:
        i_ok, _ = _docker(runner, docker, "image", "inspect", tag)
    else:
        i_ok = False
    checks.append(_check(
        "scanner_image", i_ok, False,
        "%s present" % tag if i_ok else
        "%s missing; will be built on first scan (~%d min)" % (tag, IMAGE_BUILD_MINUTES),
        "No action needed; the image is built automatically on first scan"))

    inv = discover.discover(project)
    stacks = inv["stacks"]
    s_ok = any(s in SUPPORTED_STACKS for s in stacks)
    checks.append(_check("supported_stack", s_ok, True,
                         "stacks: %s" % ", ".join(stacks) if stacks else "no supported stack found",
                         "Run the audit on a Python or JavaScript/TypeScript project "
                         "(no requirements/pyproject/package.json found)"))

    ready = all(c["ok"] for c in checks if c["blocking"])
    return {"ready": ready, "checks": checks, "git": inv["git"], "stacks": stacks}


def format_table(result: dict) -> str:
    lines = []
    for c in result["checks"]:
        mark = "OK  " if c["ok"] else ("FAIL" if c["blocking"] else "WARN")
        lines.append("[%s] %-16s %s" % (mark, c["name"], c["detail"]))
        if not c["ok"] and c["fix"]:
            lines.append("       fix: %s" % c["fix"])
    git = result["git"]
    lines.append("git: %s" % ("repo, commit %s%s" % ((git["commit"] or "none")[:12],
                                                    ", dirty" if git["dirty"] else "")
                              if git["is_repo"] else "not a git repository"))
    lines.append("Ready to audit." if result["ready"] else "NOT READY: fix the FAIL items above.")
    return "\n".join(lines)
