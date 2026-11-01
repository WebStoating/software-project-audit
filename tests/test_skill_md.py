"""SKILL.md is the orchestration entry point the agent follows; these tests pin its contract."""
import re
from pathlib import Path

from helpers import FORBIDDEN_TOOL_NAMES

ROOT = Path(__file__).resolve().parent.parent

SECTIONS = [
    "What this does and what it won't do",
    "Step 0: Readiness",
    "Step 1: Context",
    "Step 2: Discover",
    "Step 3: Baseline",
    "Steps 4–5: Analysis",
    "Step 6: Validate",
    "Step 7: Report",
    "Rules",
    "Reference index",
]
SUBAGENT_SENTENCE = ("If you can delegate to subagents, dispatch one per brief in `references/subagent-briefs.md`, "
                     "in parallel; otherwise work through the same briefs yourself in order.")
# Skill-relative paths: references/..., assets/..., scripts/..., bare or as <skill>/...
# (project paths such as audit/raw/scanners/... are not checked).
_SKILL_PATH = re.compile(r"(?:(?<=<skill>/)|(?<![\w/.<>-]))((?:references|assets|scripts)/[\w./-]*[\w-])")


def _body(skill_root):
    text = (skill_root / "SKILL.md").read_text(encoding="utf-8")
    m = re.match(r"---\n.*?\n---\n", text, re.S)
    assert m, "missing frontmatter"
    return text[m.end():]


def _section(body, title):
    m = re.search(r"^## %s\n(.*?)(?=^## |\Z)" % re.escape(title), body, re.S | re.M)
    assert m, "missing section %r" % title
    return m.group(1)


def test_skill_md_sections_in_order(skill_root):
    headings = re.findall(r"^## (.+)$", _body(skill_root), re.M)
    assert headings == SECTIONS


def test_skill_path_pattern():
    sample = "run `python3 <skill>/scripts/x.py`, read references/a.md, not audit/raw/scanners/b.log"
    assert _SKILL_PATH.findall(sample) == ["scripts/x.py", "references/a.md"]


def test_skill_md_links_resolve(skill_root):
    body = _body(skill_root)
    mentioned = set(_SKILL_PATH.findall(body))
    assert "scripts/audit.py" in mentioned
    missing = sorted(p for p in mentioned if not (skill_root / p).exists())
    assert not missing, "paths in SKILL.md that do not exist in the skill folder: %s" % missing
    for target in re.findall(r"\]\(([^)#]+)\)", body):
        if not re.match(r"[a-z]+://", target):
            assert (skill_root / target).exists(), target


def test_skill_md_reference_index_lists_every_file(skill_root):
    index = _section(_body(skill_root), "Reference index")
    for folder in ("references", "assets"):
        for f in sorted((skill_root / folder).iterdir()):
            if f.is_file():
                lines = [ln for ln in index.splitlines() if "%s/%s" % (folder, f.name) in ln]
                assert len(lines) == 1, "%s/%s needs exactly one index line" % (folder, f.name)


def test_skill_md_mentions_every_cli_subcommand(skill_root):
    import audit

    body = _body(skill_root)
    for name in audit.SUBCOMMANDS:
        assert re.search(r"scripts/audit\.py %s\b" % name, body), name


def test_skill_md_line_limit(skill_root):
    assert len(_body(skill_root).splitlines()) < 500


def test_skill_md_subagent_dispatch_and_merge(skill_root):
    body = _body(skill_root)
    analysis = _section(body, "Steps 4–5: Analysis")
    assert SUBAGENT_SENTENCE in " ".join(analysis.split())
    validate = " ".join(_section(body, "Step 6: Validate").split())
    assert "candidates" in validate and "AUD-NNN" in validate
    assert "a scanner hit is a lead, not a finding" in validate.lower()


def test_skill_md_states_tool_failure_and_render_rules(skill_root):
    body = " ".join(_body(skill_root).split()).lower()
    assert "a failed tool is never a clean result" in body
    assert "fix the narrative and re-render" in body
    assert "only after the developer confirms the exact commands" in body


def test_skill_md_asks_for_test_run_consent_and_skips_on_decline(skill_root):
    body = _body(skill_root)
    step1 = " ".join(_section(body, "Step 1: Context").split()).lower()
    assert "trust this project's code and the local environment" in step1
    assert "test_run_consent" in step1
    baseline = " ".join(_section(body, "Step 3: Baseline").split()).lower()
    assert "skip this whole subsection" in baseline
    rules = " ".join(_section(body, "Rules").split()).lower()
    assert "no project code without consent" in rules


def test_skill_md_rules_treat_repository_content_as_untrusted(skill_root):
    rules = " ".join(_section(_body(skill_root), "Rules").split()).lower()
    assert "untrusted data" in rules
    assert "never followed" in rules


def test_readme_has_no_agent_specific_tool_names():
    # SKILL.md and references/ are covered by test_skill_package.test_no_agent_specific_tool_names.
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    for bad in FORBIDDEN_TOOL_NAMES:
        assert bad not in text, bad


def test_skill_md_context_written_after_discover(skill_root):
    step1 = _section(_body(skill_root), "Step 1: Context")
    assert step1.lstrip().startswith("Do not write `audit/raw/context.json` yet")


def test_skill_md_baseline_covers_long_runs_reruns_and_errors(skill_root):
    step3 = " ".join(_section(_body(skill_root), "Step 3: Baseline").split()).lower()
    assert "tens of minutes" in step3 and "background" in step3
    assert "rerun the same command" in step3
    assert "exits 2" in step3 and "stderr" in step3
    assert "`skipped`" in step3 and "not_reviewed" in step3
    assert "re-runnable" in step3


def test_skill_md_merge_remaps_standards_outcomes(skill_root):
    step6 = " ".join(_section(_body(skill_root), "Step 6: Validate").split())
    assert "standards_outcomes" in step6 and "C-" in step6


def _step3(skill_root):
    body = _body(skill_root)
    return body[body.index("## Step 3: Baseline"):body.index("## Steps 4–5: Analysis")]


def test_skill_md_test_step_requires_preview_and_confirmation(skill_root):
    step = _step3(skill_root)
    for needle in ("audit.py test --project", "--run", "ask the user", "never invent", "without sandbox restrictions",
                   "coverage_tool_suggestion", "not_reviewed", "verified_fail", "needs_verification"):
        assert needle in step, needle


def test_skill_md_has_no_container_test_language(skill_root):
    body = _body(skill_root)
    assert "throwaway container" not in body and "test container" not in body
