import json
import re

from auditlib import SKILL_ROOT
from auditlib.methodology import load_check_ids
from auditlib.models import DOMAINS
from auditlib.references import CHECKLIST_FILES
from helpers import FORBIDDEN_TOOL_NAMES as FORBIDDEN

REFS = SKILL_ROOT / "references"
LABELS = [
    "**How to check (Python):**",
    "**How to check (JS/TS):**",
    "**Evidence to cite:**",
    "**Scanner leads:**",
    "**Common false positives:**",
]
CHECK_HEADING = re.compile(r"^### ([A-Z]+-\d{2})\s*$", re.M)
BRIEF_HEADING = re.compile(r"^## Brief: `([a-z-]+)`\s*$", re.M)
DOMAIN_BRIEFS = {
    "domains-architecture-docs", "domains-code-performance", "domains-security",
    "domains-supply-chain-delivery", "domains-data", "domains-testing-observability",
}
NEW_FILES = sorted(set(CHECKLIST_FILES.values()) | {
    "profile-python.md", "profile-javascript.md", "profile-ai-agents.md", "subagent-briefs.md"})
# Tool names specific to one agent, beyond the shared list in test_skill_package.
EXTRA_FORBIDDEN = ["Grep tool", "Glob tool", "Bash tool", "Read tool", "WebFetch", "Explore agent"]


def _sections(text):
    """Check id -> section body (text up to the next ### or ## heading)."""
    out = {}
    matches = list(CHECK_HEADING.finditer(text))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[m.end():end]
        cut = re.search(r"^##? ", body, re.M)
        out[m.group(1)] = body[:cut.start()] if cut else body
    return out


def _briefs():
    text = (REFS / "subagent-briefs.md").read_text(encoding="utf-8")
    matches = list(BRIEF_HEADING.finditer(text))
    return {m.group(1): text[m.end():(matches[i + 1].start() if i + 1 < len(matches) else len(text))]
            for i, m in enumerate(matches)}


def test_checklist_files_map_every_domain():
    assert set(CHECKLIST_FILES) == set(DOMAINS)
    assert len(set(CHECKLIST_FILES.values())) == len(CHECKLIST_FILES)


def test_every_check_has_a_checklist_section():
    for domain, ids in load_check_ids().items():
        assert ids, domain
        text = (REFS / CHECKLIST_FILES[domain]).read_text(encoding="utf-8")
        headings = CHECK_HEADING.findall(text)
        assert sorted(headings) == sorted(set(headings)), "duplicate sections in %s" % CHECKLIST_FILES[domain]
        assert set(headings) == set(ids), "%s: missing %s, unknown %s" % (
            CHECKLIST_FILES[domain], sorted(set(ids) - set(headings)), sorted(set(headings) - set(ids)))


def test_checklist_starts_with_methodology_pointer():
    for domain, name in CHECKLIST_FILES.items():
        text = (REFS / name).read_text(encoding="utf-8")
        assert "Questions: see methodology.md §4 %s" % domain in "\n".join(text.splitlines()[:5]), name


def test_checklist_sections_have_required_labels():
    for domain, name in CHECKLIST_FILES.items():
        for check, body in _sections((REFS / name).read_text(encoding="utf-8")).items():
            positions = [body.find(label) for label in LABELS]
            assert all(p >= 0 for p in positions), "%s %s lacks %s" % (
                name, check, [lab for lab, p in zip(LABELS, positions) if p < 0])
            assert positions == sorted(positions), "%s %s: labels out of order" % (name, check)
            for label in LABELS:
                after = body.split(label, 1)[1].split("**", 1)[0].strip()
                assert after, "%s %s: empty %s" % (name, check, label)


def test_checklists_do_not_restate_questions():
    questions = {}
    text = (REFS / "methodology.md").read_text(encoding="utf-8")
    for m in re.finditer(r"^\| ([A-Z]+-\d{2}) \| (.+?) \|$", text, re.M):
        questions[m.group(1)] = m.group(2)
    for name in CHECKLIST_FILES.values():
        body = (REFS / name).read_text(encoding="utf-8")
        for cid, q in questions.items():
            assert q not in body, "%s restates the %s question" % (name, cid)


def test_briefs_cover_all_domains_once():
    briefs = _briefs()
    assert set(briefs) == DOMAIN_BRIEFS | {"workflow-trace"}
    seen = []
    for bid in DOMAIN_BRIEFS:
        m = re.search(r"^\*\*Domains:\*\* (.+)$", briefs[bid], re.M)
        assert m, bid
        seen += re.findall(r"\bD\d{2}\b", m.group(1))
    assert sorted(seen) == sorted(DOMAINS), seen


def test_briefs_state_inputs_rules_output_and_boundary():
    for bid, body in _briefs().items():
        for needle in ["**Inputs:**", "**Rules:**", "**Output:**", "**Boundary:**",
                       "untrusted", "audit/raw/subagents/%s" % bid, "file:line", "C-%s" % bid,
                       "never run project code on the host", "Do not modify the project"]:
            assert needle in body, "%s brief lacks %r" % (bid, needle)


def test_security_brief_requires_every_standard_outcome():
    body = _briefs()["domains-security"]
    for needle in ["references/owasp-top10-2025.md", "references/cwe-top25.md", "all 10", "all 25",
                   "standards_outcomes"]:
        assert needle in body, needle


def test_briefs_reference_existing_files():
    for name in NEW_FILES:
        text = (REFS / name).read_text(encoding="utf-8")
        for ref in re.findall(r"\b((?:references|assets)/[A-Za-z0-9_.-]+\.(?:md|json))\b", text):
            assert (SKILL_ROOT / ref).is_file(), "%s names missing %s" % (name, ref)


def test_reference_files_name_no_agent_specific_tools():
    for name in NEW_FILES:
        text = (REFS / name).read_text(encoding="utf-8")
        for bad in FORBIDDEN + EXTRA_FORBIDDEN:
            assert bad not in text, "%s names %s" % (name, bad)


def test_reference_files_stay_focused():
    for name in NEW_FILES:
        n = len((REFS / name).read_text(encoding="utf-8").splitlines())
        assert n < 400, "%s has %d lines" % (name, n)


def test_scanner_leads_name_only_shipped_tools():
    """Every reference file (except the methodology copy) cites only tools and Semgrep packs the image ships."""
    banned = ["Radon", "pip-audit", "npm audit", "dependency-cruiser", "Snyk"]
    shipped = set(json.loads((SKILL_ROOT / "assets" / "tool-versions.json").read_text())["semgrep_packs"])
    files = [p for p in sorted(REFS.glob("*.md")) if p.name != "methodology.md"]
    assert len(files) >= len(NEW_FILES) + 2
    for path in files:
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"\*\*Scanner leads:\*\*(.*)", text):
            for bad in banned:
                assert bad not in m.group(1), "%s cites %s as a lead" % (path.name, bad)
        for pack in re.findall(r"\b([pr]/[a-z0-9._-]+)", text):
            pack = pack.rstrip(".")
            assert pack in shipped, "%s cites unshipped Semgrep pack %s" % (path.name, pack)
