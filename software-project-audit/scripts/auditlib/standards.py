"""Access to the OWASP Top 10:2025 and CWE Top 25 lists in assets/standards.json."""
import json
from typing import List

from . import SKILL_ROOT


def load_standards() -> dict:
    path = SKILL_ROOT / "assets" / "standards.json"
    return json.loads(path.read_text(encoding="utf-8"))


def owasp_ids() -> List[str]:
    return [i["id"] for i in load_standards()["owasp_top10_2025"]["items"]]


def cwe_ids() -> List[str]:
    return [i["id"] for i in load_standards()["cwe_top25"]["items"]]
