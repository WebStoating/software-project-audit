import subprocess
from pathlib import Path

import pytest

from helpers import SKILL_DIR


@pytest.fixture
def skill_root() -> Path:
    return SKILL_DIR


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).resolve().parent / "fixtures"


def _docker_available() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def pytest_collection_modifyitems(config, items):
    if not any(i.get_closest_marker("docker") for i in items):
        return
    if _docker_available():
        return
    skip = pytest.mark.skip(reason="Docker daemon not available")
    for item in items:
        if item.get_closest_marker("docker"):
            item.add_marker(skip)


# Planted-issue fixture projects contain their own (deliberately failing) tests; never collect them.
collect_ignore = ["fixtures"]
