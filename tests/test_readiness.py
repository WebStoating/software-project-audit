import json
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from auditlib import readiness
from helpers import make_fixture_repo

AUDIT_PY = Path(__file__).resolve().parent.parent / "software-project-audit" / "scripts" / "audit.py"


class _Handler(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        _Handler.seen.append((self.headers.get("Content-Type"), body))
        self.send_response(400)  # any HTTP status counts as reachable
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def probe_server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d/v1/query" % srv.server_port
    srv.shutdown()
    srv.server_close()


def _free_port_url():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return "http://127.0.0.1:%d/" % port


def fake_runner(fail=(), image_present=True, stderr="boom"):
    calls = []

    def run(argv, **kw):
        calls.append(argv)
        key = "image" if argv[1] == "image" else argv[1].lstrip("-")
        bad = key in fail or (key == "image" and not image_present)
        return subprocess.CompletedProcess(argv, 1 if bad else 0, "Docker version 29\n", stderr if bad else "")
    run.calls = calls
    return run


@pytest.fixture
def pyproj(tmp_path):
    return make_fixture_repo("py-app", tmp_path)


def by_name(result):
    return {c["name"]: c for c in result["checks"]}


def test_ready_when_all_ok(pyproj, probe_server):
    runner = fake_runner()
    res = readiness.check_readiness(pyproj, probe_url=probe_server, runner=runner)
    assert res["ready"] is True
    assert [c["name"] for c in res["checks"]] == [
        "python", "docker_cli", "docker_daemon", "network", "scanner_image", "supported_stack"]
    assert all(c["ok"] for c in res["checks"])
    assert res["stacks"] == ["python"] and res["git"]["is_repo"]
    assert _Handler.seen[-1] == ("application/json", b"{}")
    assert [c[1] for c in runner.calls] == ["--version", "info", "image"]
    assert not (pyproj / "audit").exists()


def test_docker_daemon_down_is_blocking_with_fix(pyproj, probe_server):
    res = readiness.check_readiness(pyproj, probe_url=probe_server, runner=fake_runner(fail=("info",)))
    c = by_name(res)["docker_daemon"]
    assert not res["ready"] and not c["ok"] and c["blocking"]
    assert c["fix"] == "Start Docker Desktop and rerun"


def test_docker_not_installed(pyproj, probe_server):
    res = readiness.check_readiness(pyproj, docker="/nonexistent/docker", probe_url=probe_server)
    c = by_name(res)["docker_cli"]
    assert not c["ok"] and c["blocking"] and "docs.docker.com/get-docker" in c["fix"]
    assert not res["ready"]


def test_docker_socket_denied_suggests_sandbox_fix(pyproj, probe_server):
    res = readiness.check_readiness(pyproj, probe_url=probe_server,
                                    runner=fake_runner(fail=("info",), stderr="permission denied on docker.sock"))
    assert "sandbox mode" in by_name(res)["docker_daemon"]["fix"]


def test_network_unreachable_is_blocking(pyproj):
    res = readiness.check_readiness(pyproj, probe_url=_free_port_url(), runner=fake_runner())
    c = by_name(res)["network"]
    assert not res["ready"] and not c["ok"] and c["blocking"]
    assert "Allow network access" in c["fix"]


def test_missing_scanner_image_not_blocking(pyproj, probe_server):
    res = readiness.check_readiness(pyproj, probe_url=probe_server, runner=fake_runner(image_present=False))
    c = by_name(res)["scanner_image"]
    assert res["ready"] is True
    assert not c["ok"] and not c["blocking"]
    assert "will be built on first scan (~" in c["detail"]


def test_no_supported_stack_blocks(tmp_path, probe_server):
    (tmp_path / "go.mod").write_text("module x\n")
    res = readiness.check_readiness(tmp_path, probe_url=probe_server, runner=fake_runner())
    c = by_name(res)["supported_stack"]
    assert not res["ready"] and not c["ok"] and c["blocking"] and c["fix"]
    assert not (tmp_path / "audit").exists()


def _fake_docker(tmp_path, ok):
    script = tmp_path / "bin" / "docker"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\nexit %d\n" % (0 if ok else 1))
    script.chmod(0o755)
    return str(script)


def test_cli_exit_codes(tmp_path, pyproj, probe_server):
    def run(docker, *extra):
        return subprocess.run([sys.executable, str(AUDIT_PY), "readiness", "--project", str(pyproj),
                               "--docker", docker, "--probe-url", probe_server, *extra],
                              capture_output=True, text=True)

    ok = run(_fake_docker(tmp_path, True), "--json")
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert json.loads(ok.stdout)["ready"] is True
    (tmp_path / "x").mkdir()
    bad = run(_fake_docker(tmp_path / "x", False))
    assert bad.returncode == 2
    assert "NOT READY" in bad.stdout and "Install Docker Desktop" in bad.stdout
    assert not (pyproj / "audit").exists()
