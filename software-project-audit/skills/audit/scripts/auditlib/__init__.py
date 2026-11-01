"""Support library for the software-project-audit skill (stdlib only)."""
import re
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent.parent


def _read_version() -> str:
    text = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    if m:
        v = re.search(r'^metadata:\s*\n(?:[ \t]+.*\n)*?[ \t]+version:\s*"?([^"\n]+)"?', m.group(1) + "\n", re.M)
        if v:
            return v.group(1).strip()
    raise RuntimeError("metadata.version not found in SKILL.md frontmatter")


SKILL_VERSION: str = _read_version()
