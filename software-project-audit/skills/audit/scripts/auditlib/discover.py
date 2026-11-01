"""Deterministic repository discovery: stacks, packages, CI/infra files and git state."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path, PurePosixPath

EXCLUDED_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
    ".next", ".nuxt", "coverage", "htmlcov", "audit", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".turbo",
})

PY_LOCKS = (("uv.lock", "uv"), ("poetry.lock", "poetry"), ("Pipfile.lock", "pipenv"))
JS_LOCKS = (("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn"), ("package-lock.json", "npm"))
JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
CI_NAMES = {".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml", "bitbucket-pipelines.yml",
            ".travis.yml", ".drone.yml"}
IAC_NAMES = {"Pulumi.yaml", "cdk.json", "serverless.yml", "serverless.yaml", "Chart.yaml",
             "helmfile.yaml"}
IAC_EXTS = {".tf", ".tfvars", ".bicep"}
K8S_DIRS = {"k8s", "kubernetes", "manifests", "helm", "charts"}
ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template", ".env.dist", "env.example"}
MIGRATION_DIRS = {"migrations", "alembic", "migrate"}
DOC_PREFIXES = ("README", "CONTRIBUTING", "SECURITY", "CHANGELOG", "LICENSE", "ARCHITECTURE",
                "CODE_OF_CONDUCT")
UNSUPPORTED = (
    ("dotnet", {"*.csproj", "*.sln"}), ("go", {"go.mod"}),
    ("java", {"pom.xml", "build.gradle", "build.gradle.kts"}), ("ruby", {"Gemfile"}),
    ("php", {"composer.json"}), ("rust", {"Cargo.toml"}),
)
NPM_DEFAULT_TEST = 'echo "Error: no test specified"'
AI_EXACT = {"openai", "anthropic", "ai", "@anthropic-ai/sdk"}
AI_PREFIXES = ("langchain", "llama-index", "@ai-sdk/", "@langchain/")


def _git(project: Path, *args: str) -> "subprocess.CompletedProcess | None":
    # The audited repo is untrusted: neutralise config that would make git execute commands.
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
    try:
        return subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                               "-C", str(project), *args], capture_output=True,
                              text=True, env=env, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None


def _worktree_differs(project: Path) -> bool:
    """Compare tracked files with the index by hashing content ourselves (no git filters run).

    Files git would convert (eol, clean filters) may be over-reported as dirty; that is acceptable.
    """
    fmt = _git(project, "rev-parse", "--show-object-format")
    algo = "sha256" if fmt is not None and fmt.returncode == 0 and fmt.stdout.strip() == "sha256" else "sha1"
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
    try:
        r = subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                            "-C", str(project), "ls-files", "-s", "-z"],
                           capture_output=True, env=env, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return True
    if r.returncode != 0:
        return True
    for entry in r.stdout.split(b"\0"):
        if not entry:
            continue
        meta, _, raw_path = entry.partition(b"\t")
        parts = meta.split()
        if len(parts) != 3:
            return True
        mode, oid, stage = parts[0], parts[1].decode(), parts[2]
        path = os.fsdecode(raw_path)
        if mode == b"160000" or path == "audit" or path.startswith("audit/"):
            continue
        full = os.path.join(str(project), path)
        try:
            if mode == b"120000":
                data = os.fsencode(os.readlink(full))
            else:
                if os.path.islink(full):
                    return True
                with open(full, "rb") as fh:
                    data = fh.read()
        except OSError:
            return True
        digest = hashlib.new(algo, b"blob %d\0" % len(data) + data).hexdigest()
        if digest != oid or stage != b"0":
            return True
    return False


def _git_info(project: Path) -> dict:
    info = {"is_repo": False, "commit": None, "branch": None, "dirty": False, "has_commits": False}
    r = _git(project, "rev-parse", "--is-inside-work-tree")
    if r is None or r.returncode != 0 or r.stdout.strip() != "true":
        return info
    info["is_repo"] = True
    head = _git(project, "rev-parse", "--verify", "HEAD")
    if head is not None and head.returncode == 0:
        info["has_commits"] = True
        info["commit"] = head.stdout.strip()
    br = _git(project, "symbolic-ref", "--short", "-q", "HEAD")
    if br is not None and br.returncode == 0:
        info["branch"] = br.stdout.strip() or None
    # Never `git status`/`diff`/`diff-files`/`add`: any command that compares the worktree to the
    # index can run fsmonitor or clean/process filter drivers from the untrusted repo's config.
    # Only index-vs-HEAD and index-listing plumbing is used; worktree content is hashed in Python.
    dirty = False
    if info["has_commits"]:
        r = _git(project, "diff-index", "--quiet", "--cached", "--no-ext-diff", "HEAD", "--")
        dirty = r is None or r.returncode != 0
    if not dirty:
        dirty = _worktree_differs(project)
    if not dirty:
        r = _git(project, "ls-files", "--others", "--exclude-standard", "--", ".", ":!audit")
        dirty = r is None or r.returncode != 0 or bool(r.stdout.strip())
    info["dirty"] = dirty
    return info


def _walk(project: Path):
    """Yield (relative posix dir, [dirnames], [filenames]); prunes excluded dirs, skips symlinks."""
    for root, dirs, files in os.walk(str(project), followlinks=False):
        dirs[:] = sorted(d for d in dirs
                         if d not in EXCLUDED_DIRS and not os.path.islink(os.path.join(root, d)))
        files = sorted(f for f in files if not os.path.islink(os.path.join(root, f)))
        rel = os.path.relpath(root, str(project))
        yield ("." if rel == "." else PurePosixPath(*Path(rel).parts).as_posix()), dirs, files


def _read(path: Path, limit: int = 1_000_000) -> str:
    try:
        with open(str(path), "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _join(d: str, name: str) -> str:
    return name if d == "." else d + "/" + name


def _is_yaml(name: str) -> bool:
    return name.endswith((".yml", ".yaml"))


def _py_names(text: str) -> set:
    names = set()
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z][A-Za-z0-9_.\-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~;@ ]|$)", line)
        if m and not line.lstrip().startswith("#"):
            names.add(m.group(1))
        names.update(re.findall(
            r"""["']([A-Za-z][A-Za-z0-9_.\-]*)(?:\[[^\]]*\])?\s*(?:[<>=!~;@ ][^"']*)?["']""", line))
        m = re.match(r"^\s*([A-Za-z][A-Za-z0-9_.\-]*)\s*=", line)
        if m:
            names.add(m.group(1))
    return {n.lower().replace("_", "-") for n in names}


def _ai_matches(names) -> set:
    return {n for n in names if n in AI_EXACT or n.startswith(AI_PREFIXES)}


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(_read(path))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _py_runtime(pkg_dir: Path, pyproject_text: str):
    pv = pkg_dir / ".python-version"
    if pv.is_file():
        lines = _read(pv).strip().splitlines()
        m = re.match(r"^\s*(\d+)\.(\d+)", lines[0]) if lines else None
        if m:
            return "%s.%s" % (m.group(1), m.group(2)), ".python-version"
    m = re.search(r"""requires-python\s*=\s*["']([^"']+)["']""", pyproject_text)
    if m:
        vers = [(int(a), int(b)) for a, b in re.findall(r"(?:>=|~=|==|>)\s*(\d+)\.(\d+)", m.group(1))]
        if vers:
            lo = min(vers)
            return "%d.%d" % lo, "pyproject.toml"
    return None, None


def _js_runtime(pkg_dir: Path, pkg_json: dict):
    for name in (".nvmrc", ".node-version"):
        f = pkg_dir / name
        if f.is_file():
            text = _read(f).strip()
            m = re.search(r"(\d+)", text.splitlines()[0]) if text else None
            if m:
                return m.group(1), name
    node = (pkg_json.get("engines") or {}).get("node") if isinstance(pkg_json.get("engines"), dict) else None
    if isinstance(node, str):
        m = re.search(r"(\d+)", node)
        if m:
            return m.group(1), "package.json"
    return None, None


def _owner(path: str, pkg_paths: list) -> "str | None":
    """Deepest package path that contains this file."""
    best = None
    for p in pkg_paths:
        if p == "." or path.startswith(p + "/"):
            if best is None or len(p) > len(best) or best == ".":
                best = p
    return best


def discover(project: Path) -> dict:
    project = Path(project)
    all_files = []  # relative posix paths
    all_dirs = []
    dir_files = {}
    for rel, dirs, files in _walk(project):
        dir_files[rel] = files
        all_dirs.extend(_join(rel, d) for d in dirs)
        all_files.extend(_join(rel, f) for f in files)

    counts = {}
    for f in all_files:
        ext = os.path.splitext(f)[1].lower() or "(none)"
        counts[ext] = counts.get(ext, 0) + 1

    # --- packages ---
    packages = []
    ai = set()
    for d in sorted(dir_files):
        files = set(dir_files[d])
        pdir = project if d == "." else project / d
        req = sorted(f for f in files if re.match(r"^requirements.*\.txt$", f))
        py_lock = next(((lf, m) for lf, m in PY_LOCKS if lf in files), None)
        if py_lock or req or "pyproject.toml" in files or "Pipfile" in files:
            pyproject = _read(pdir / "pyproject.toml") if "pyproject.toml" in files else ""
            if py_lock:
                lockfile, manager = py_lock
            elif req:
                lockfile, manager = None, "pip"
            else:
                lockfile, manager = None, ("pipenv" if "Pipfile" in files else "pip")
            if "pyproject.toml" in files and (py_lock or not req):
                manifest = "pyproject.toml"
            elif "Pipfile" in files and manager == "pipenv":
                manifest = "Pipfile"
            else:
                manifest = "requirements.txt" if "requirements.txt" in req else (req[0] if req else "pyproject.toml")
            texts = [pyproject] + [_read(pdir / f) for f in req]
            if "Pipfile" in files:
                texts.append(_read(pdir / "Pipfile"))
            blob = "\n".join(texts)
            ai |= _ai_matches(_py_names(blob))
            version, source = _py_runtime(pdir, pyproject)
            packages.append({
                "path": d, "ecosystem": "python", "manager": manager, "manifest": manifest,
                "lockfile": lockfile, "runtime_version": version, "runtime_version_source": source,
                "_blob": blob,
            })
        if "package.json" in files:
            pj = _load_json(pdir / "package.json")
            deps = {}
            for key in ("dependencies", "devDependencies"):
                if isinstance(pj.get(key), dict):
                    deps.update(pj[key])
            ai |= _ai_matches(set(deps))
            lock = next(((lf, m) for lf, m in JS_LOCKS if lf in files), None)
            version, source = _js_runtime(pdir, pj)
            scripts = pj.get("scripts") if isinstance(pj.get("scripts"), dict) else {}
            test_script = scripts.get("test")
            if "vitest" in deps:
                runner = "vitest"
            elif "jest" in deps:
                runner = "jest"
            elif isinstance(test_script, str) and test_script.strip() and \
                    not test_script.strip().startswith(NPM_DEFAULT_TEST):
                runner = "script"
            else:
                runner = None
            packages.append({
                "path": d, "ecosystem": "javascript", "manager": lock[1] if lock else "npm",
                "manifest": "package.json", "lockfile": lock[0] if lock else None,
                "runtime_version": version, "runtime_version_source": source,
                "test_runner": runner,
            })

    # --- tests per package ---
    for eco in ("python", "javascript"):
        paths = [p["path"] for p in packages if p["ecosystem"] == eco]
        has = {p: False for p in paths}
        conftest = {p: False for p in paths}
        for f in all_files:
            owner = _owner(f, paths)
            if owner is None:
                continue
            name = f.rsplit("/", 1)[-1]
            parts = f.split("/")
            if eco == "python":
                if name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py")):
                    has[owner] = True
                if name == "conftest.py" or name == "pytest.ini":
                    conftest[owner] = True
            elif re.search(r"\.(test|spec)\.[cm]?[jt]sx?$", name) or "__tests__" in parts[:-1]:
                has[owner] = True
        for p in packages:
            if p["ecosystem"] != eco:
                continue
            p["has_tests"] = has[p["path"]]
            if eco == "python":
                blob = p.pop("_blob")
                is_pytest = (re.search(r"(?im)\bpytest\b", blob) or "[tool.pytest" in blob
                             or conftest[p["path"]] or has[p["path"]])
                p["test_runner"] = "pytest" if is_pytest else None
    packages.sort(key=lambda p: (p["path"], p["ecosystem"]))
    keys = ("path", "ecosystem", "manager", "manifest", "lockfile", "runtime_version",
            "runtime_version_source", "test_runner", "has_tests")
    packages = [{k: p[k] for k in keys} for p in packages]

    # --- stacks ---
    stacks = sorted({p["ecosystem"] for p in packages})
    if not packages:
        if counts.get(".py"):
            stacks.append("python")
        if any(counts.get(e) for e in JS_EXTS):
            stacks.append("javascript")
        stacks.sort()

    # --- infrastructure files ---
    ci, dockerfiles, compose, iac, env_templates, docs, k8s = [], [], [], [], [], [], []
    workflows = False
    for f in all_files:
        name = f.rsplit("/", 1)[-1]
        ext = os.path.splitext(name)[1].lower()
        in_wf = "/.github/workflows/" in "/" + f and _is_yaml(name)
        if in_wf:
            workflows = True
        is_ci = in_wf or name in CI_NAMES or (_is_yaml(name) and f.endswith(".circleci/config.yml"))
        if is_ci:
            ci.append(f)
        if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
            dockerfiles.append(f)
        is_compose = bool(re.match(r"^(docker-)?compose(\..+)?\.ya?ml$", name))
        if is_compose:
            compose.append(f)
        if name in IAC_NAMES or ext in IAC_EXTS:
            iac.append(f)
        if name in ENV_TEMPLATES or name.endswith(".env.example"):
            env_templates.append(f)
        if name.startswith(DOC_PREFIXES) or (f.split("/")[0] == "docs" and ext in {".md", ".rst", ".txt"}):
            docs.append(f)
        if _is_yaml(name) and not is_ci and not is_compose and name not in IAC_NAMES:
            in_k8s_dir = bool(K8S_DIRS & set(f.split("/")[:-1]))
            head = _read(project / f, 65536)
            if re.search(r"(?m)^apiVersion:", head) and re.search(r"(?m)^kind:", head) or \
                    (in_k8s_dir and re.search(r"(?m)^kind:", head)):
                k8s.append(f)
    migrations = [d for d in all_dirs if d.rsplit("/", 1)[-1] in MIGRATION_DIRS]

    unsupported = set()
    for f in all_files:
        name = f.rsplit("/", 1)[-1]
        for label, pats in UNSUPPORTED:
            if any(fnmatch.fnmatchcase(name, pat) for pat in pats):
                unsupported.add(label)

    return {
        "project": str(project.resolve()),
        "git": _git_info(project),
        "stacks": stacks,
        "packages": packages,
        "ci_files": sorted(ci),
        "github_workflows": workflows,
        "dockerfiles": sorted(dockerfiles),
        "compose_files": sorted(compose),
        "iac_files": sorted(iac),
        "k8s_files": sorted(k8s),
        "env_templates": sorted(env_templates),
        "migrations_dirs": sorted(migrations),
        "docs": sorted(docs),
        "ai_sdks": sorted(ai),
        "unsupported_stacks": sorted(unsupported),
        "file_counts": dict(sorted(counts.items())),
    }


def summary(inv: dict) -> str:
    g = inv["git"]
    lines = [
        "Project: %s" % inv["project"],
        "Git: %s" % ("repo, %s%s" % (g["branch"] or "detached", ", dirty" if g["dirty"] else "")
                     if g["is_repo"] else "not a git repository"),
        "Stacks: %s" % (", ".join(inv["stacks"]) or "none detected"),
        "Packages: %d" % len(inv["packages"]),
    ]
    for p in inv["packages"]:
        lines.append("  %s [%s/%s] runtime=%s tests=%s runner=%s" % (
            p["path"], p["ecosystem"], p["manager"], p["runtime_version"] or "?",
            "yes" if p["has_tests"] else "no", p["test_runner"] or "none"))
    lines.append("CI files: %d | Dockerfiles: %d | IaC: %d | k8s: %d"
                 % (len(inv["ci_files"]), len(inv["dockerfiles"]), len(inv["iac_files"]), len(inv["k8s_files"])))
    if inv["ai_sdks"]:
        lines.append("AI SDKs: %s" % ", ".join(inv["ai_sdks"]))
    if inv["unsupported_stacks"]:
        lines.append("Unsupported stacks (not audited by scanners): %s" % ", ".join(inv["unsupported_stacks"]))
    return "\n".join(lines)
