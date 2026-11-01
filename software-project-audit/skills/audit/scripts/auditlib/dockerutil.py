"""Docker helpers: subprocess wrapper, scanner image build, scanner container argv."""
from __future__ import annotations

import hashlib
import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import SKILL_ROOT, SKILL_VERSION
from .paths import AuditPaths

ASSETS_DIR = SKILL_ROOT / "assets"
DOCKERFILE = ASSETS_DIR / "scanner.Dockerfile"
TOOL_VERSIONS = ASSETS_DIR / "tool-versions.json"



def image_tag(versions_bytes: bytes, dockerfile_bytes: bytes) -> str:
    """Tag that changes whenever any pin, rule pack or the Dockerfile changes."""
    h = hashlib.sha256(versions_bytes + dockerfile_bytes).hexdigest()[:12]
    return "software-project-audit-scanners:%s-%s" % (SKILL_VERSION, h)


SCANNER_IMAGE = image_tag(TOOL_VERSIONS.read_bytes(), DOCKERFILE.read_bytes())
SCANNER_USER = "10001:10001"
BUILD_TIMEOUT = 1800


@dataclass
class CompletedRun:
    exit_code: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    duration_s: float


def _text(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def run(argv: list, timeout: int, input_bytes: Optional[bytes] = None) -> CompletedRun:
    """Run argv (never a shell). Never raises on non-zero exit, timeout or a missing executable."""
    start = time.monotonic()
    try:
        r = subprocess.run(argv, input=input_bytes, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return CompletedRun(None, _text(exc.stdout), _text(exc.stderr), True, time.monotonic() - start)
    except OSError as exc:
        return CompletedRun(None, "", "%s: %s" % (type(exc).__name__, exc), False, time.monotonic() - start)
    return CompletedRun(r.returncode, _text(r.stdout), _text(r.stderr), False, time.monotonic() - start)


def image_exists(tag: str) -> bool:
    return run(["docker", "image", "inspect", tag], timeout=60).exit_code == 0


def image_digest(tag: str) -> Optional[str]:
    """Local image ID (sha256:...) or None when the image is absent."""
    r = run(["docker", "image", "inspect", "--format", "{{.Id}}", tag], timeout=60)
    out = r.stdout.strip()
    return out if r.exit_code == 0 and out else None


def load_versions() -> dict:
    return json.loads(TOOL_VERSIONS.read_text(encoding="utf-8"))


def _env_name(name: str) -> str:
    return name.upper().replace("-", "_")


def _arch_args(prefix: str, entry: dict) -> list:
    """URL and checksum build args for one downloaded artifact, per architecture."""
    out = []
    for arch in ("amd64", "arm64"):
        url = entry["url_template"].format(version=entry["version"], arch=entry["arch_names"][arch])
        out.append((prefix + "_URL_" + arch.upper(), url))
    for arch in ("amd64", "arm64"):
        out.append((prefix + "_SHA256_" + arch.upper(), entry["sha256"][arch]))
    return out


def build_args(versions: dict) -> list:
    """Flattened `--build-arg K=V` list. `coverage_tools` is consumed by testplan, not the Dockerfile."""
    pairs = [("BASE_IMAGE", versions["base_image"]), ("NODE_VERSION", versions["node"]["version"])]
    pairs += _arch_args("NODE", versions["node"])
    for name, entry in versions["binaries"].items():
        prefix = _env_name(name)
        pairs.append((prefix + "_VERSION", entry["version"]))
        pairs += _arch_args(prefix, entry)
    for name, ver in versions["pip"].items():
        pairs.append(("PY_%s_VERSION" % _env_name(name), ver))
    for name, ver in versions["npm"].items():
        pairs.append(("NPM_%s_VERSION" % _env_name(name), ver))
    pairs.append(("SEMGREP_PACKS", " ".join(versions["semgrep_packs"])))
    argv = []
    for key, value in pairs:
        argv += ["--build-arg", "%s=%s" % (key, value)]
    return argv


def build_scanner_image(force: bool = False) -> CompletedRun:
    if not force and image_exists(SCANNER_IMAGE):
        return CompletedRun(0, "%s already present" % SCANNER_IMAGE, "", False, 0.0)
    argv = ["docker", "build", "-t", SCANNER_IMAGE, *build_args(load_versions()),
            "-f", str(DOCKERFILE), str(ASSETS_DIR)]
    return run(argv, timeout=BUILD_TIMEOUT)


def ensure_scanner_out(paths: AuditPaths) -> Path:
    """Create raw/scanners and make it writable by the container user (uid 10001)."""
    out = paths.raw / "scanners"
    out.mkdir(parents=True, exist_ok=True)
    try:
        out.chmod(0o777)
    except OSError:
        pass
    return out


def scanner_run_argv(paths: AuditPaths, tool_argv: list) -> list:
    """argv for one scanner container: read-only project, writable /out, no host env."""
    return ["docker", "run", "--rm", "--user", SCANNER_USER, "--network", "bridge",
            "-v", "%s:/src:ro" % paths.project, "-v", "%s/scanners:/out" % paths.raw,
            "--tmpfs", "/tmp", SCANNER_IMAGE, *tool_argv]
