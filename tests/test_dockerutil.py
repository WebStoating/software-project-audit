import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "software-project-audit" / "scripts"))

from auditlib import SKILL_ROOT, SKILL_VERSION, dockerutil  # noqa: E402
from auditlib.paths import AuditPaths  # noqa: E402

DOCKERFILE = SKILL_ROOT / "assets" / "scanner.Dockerfile"
VERSIONS = SKILL_ROOT / "assets" / "tool-versions.json"


def _versions():
    return json.loads(VERSIONS.read_text(encoding="utf-8"))


def _dockerfile_args():
    text = DOCKERFILE.read_text(encoding="utf-8")
    return set(re.findall(r"^ARG ([A-Z0-9_]+)", text, re.M))


def _build_arg_names():
    argv = dockerutil.build_args(_versions())
    assert argv[0::2] == ["--build-arg"] * (len(argv) // 2)
    return {a.split("=", 1)[0] for a in argv[1::2]}


def test_build_args_cover_every_dockerfile_arg():
    names = _build_arg_names()
    needed = _dockerfile_args() - {"TARGETARCH"}
    assert needed <= names, "ARG without a value: %s" % sorted(needed - names)
    assert names <= _dockerfile_args(), "unused build arg: %s" % sorted(names - _dockerfile_args())


def test_dockerfile_args_have_no_defaults():
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert not re.findall(r"^ARG [A-Z0-9_]+=", text, re.M)


def test_coverage_tools_are_not_build_args():
    assert not any("PYTEST_COV" in n or n.startswith("COVERAGE") for n in _build_arg_names())


def test_every_binary_and_node_has_both_arch_checksums():
    v = _versions()
    for name, b in v["binaries"].items():
        for arch in ("amd64", "arm64"):
            assert re.fullmatch(r"[0-9a-f]{64}", b["sha256"][arch]), (name, arch)
        assert b["checksum_source"].startswith("https://")
    for arch in ("amd64", "arm64"):
        assert re.fullmatch(r"[0-9a-f]{64}", v["node"]["sha256"][arch])


def test_no_latest_tags():
    assert ":latest" not in DOCKERFILE.read_text(encoding="utf-8")
    assert ":latest" not in VERSIONS.read_text(encoding="utf-8")
    v = _versions()
    assert "@sha256:" in v["base_image"]
    assert all(re.fullmatch(r"\d+\.\d+\.\d+", ver) for ver in v["coverage_tools"].values())


def test_scanner_image_single_source():
    assert dockerutil.SCANNER_IMAGE.startswith("software-project-audit-scanners:%s-" % SKILL_VERSION)
    assert dockerutil.SCANNER_IMAGE == dockerutil.image_tag(
        dockerutil.TOOL_VERSIONS.read_bytes(), dockerutil.DOCKERFILE.read_bytes())
    from auditlib import readiness
    assert not hasattr(readiness, "scanner_image_tag")


def test_scanner_argv_quotes_path_with_spaces():
    project = Path("/tmp/Client Projects/Café")
    paths = AuditPaths.for_project(project)
    argv = dockerutil.scanner_run_argv(paths, ["ruff", "--version"])
    vols = [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]
    assert vols[0] == "/tmp/Client Projects/Café:/src:ro"
    assert vols[1] == "/tmp/Client Projects/Café/audit/raw/scanners:/out"
    assert argv[:8] == ["docker", "run", "--rm", "--user", "10001:10001", "--network", "bridge", "-v"]
    assert argv[-4:] == ["--tmpfs", "/tmp", dockerutil.SCANNER_IMAGE, "ruff"] or \
        argv[-5:] == ["--tmpfs", "/tmp", dockerutil.SCANNER_IMAGE, "ruff", "--version"]
    assert "-e" not in argv and "--env" not in argv


def test_run_timeout_does_not_raise():
    r = dockerutil.run(["sleep", "5"], timeout=1)
    assert r.timed_out is True
    assert r.exit_code is None
    assert r.duration_s < 4


def test_run_nonzero_and_missing_binary_do_not_raise():
    r = dockerutil.run([sys.executable, "-c", "import sys; print('o'); sys.stderr.write('e'); sys.exit(3)"], timeout=20)
    assert (r.exit_code, r.stdout.strip(), r.stderr, r.timed_out) == (3, "o", "e", False)
    r = dockerutil.run(["definitely-not-a-binary-xyz"], timeout=5)
    assert r.exit_code is None and not r.timed_out and r.stderr


def test_run_passes_stdin():
    r = dockerutil.run([sys.executable, "-c", "import sys; print(sys.stdin.read().upper())"], timeout=20,
                       input_bytes=b"abc")
    assert r.stdout.strip() == "ABC"


def test_build_args_values_come_from_versions():
    argv = dockerutil.build_args(_versions())
    flat = dict(a.split("=", 1) for a in argv[1::2])
    v = _versions()
    assert flat["BASE_IMAGE"] == v["base_image"]
    assert flat["NODE_VERSION"] == v["node"]["version"]
    assert flat["NODE_SHA256_ARM64"] == v["node"]["sha256"]["arm64"]
    assert flat["PY_SEMGREP_VERSION"] == v["pip"]["semgrep"]
    assert flat["NPM_JSCPD_VERSION"] == v["npm"]["jscpd"]
    assert flat["SEMGREP_PACKS"] == " ".join(v["semgrep_packs"])
    assert flat["GITLEAKS_SHA256_AMD64"] == v["binaries"]["gitleaks"]["sha256"]["amd64"]
    assert flat["GITLEAKS_URL_ARM64"].startswith("https://") and "{" not in flat["GITLEAKS_URL_ARM64"]


def test_scanner_image_tag_changes_with_pins():
    v, d = b'{"pip": {"ruff": "1"}}', b"FROM x\n"
    base = dockerutil.image_tag(v, d)
    assert base == dockerutil.image_tag(v, d)
    assert dockerutil.image_tag(v.replace(b'"1"', b'"2"'), d) != base
    assert dockerutil.image_tag(v, d + b"RUN true\n") != base
    assert re.fullmatch(r"software-project-audit-scanners:%s-[0-9a-f]{12}" % re.escape(SKILL_VERSION), base)


def test_trivy_pin_is_a_post_incident_release():
    """Trivy v0.69.4 (binaries) and 0.69.5/0.69.6 (Docker Hub) were malicious (GHSA-69fq-xp46-6x23)."""
    t = _versions()["binaries"]["trivy"]
    version = tuple(int(x) for x in t["version"].split("."))
    assert version > (0, 69, 6), t["version"]
    assert t["advisory"] == "https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23"
    assert t["checksum_source"] == (
        "https://github.com/aquasecurity/trivy/releases/download/v%s/trivy_%s_checksums.txt"
        % (t["version"], t["version"]))
    assert t["checksum_signature"] == t["checksum_source"] + ".sigstore.json"
    assert t["arch_names"] == {"amd64": "64bit", "arm64": "ARM64"}
    flat = dict(a.split("=", 1) for a in dockerutil.build_args(_versions())[1::2])
    assert flat["TRIVY_URL_ARM64"].endswith("/trivy_%s_Linux-ARM64.tar.gz" % t["version"])
    assert flat["TRIVY_SHA256_AMD64"] == t["sha256"]["amd64"]
