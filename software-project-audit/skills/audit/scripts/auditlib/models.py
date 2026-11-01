"""Shared vocabularies and records (values copied exactly from references/methodology.md)."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field

SCANNER_STATES = (
    "completed", "partial", "failed", "unavailable",
    "not_applicable", "not_requested", "blocked_by_permissions",
)
CHECK_OUTCOMES = (
    "verified_pass", "verified_fail", "reviewed_no_issue",
    "needs_verification", "not_reviewed", "not_applicable",
)
CLASSIFICATIONS = ("defect", "risk", "technical_debt", "improvement_opportunity", "accepted_tradeoff")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
CONFIDENCES = ("Confirmed", "Strongly supported", "Potential", "Unverified")
STATUSES = ("Reviewed", "Needs verification")
PRIORITIES = ("P0", "P1", "P2", "P3")
EFFORTS = ("Small", "Medium", "Large", "Unknown")
READINESS = (
    "Ready within reviewed scope",
    "Ready with conditions",
    "Not ready — identified blockers",
    "Insufficient evidence to determine readiness",
)
DOMAINS = {
    "D01": "Architecture and design",
    "D02": "Code quality and maintainability",
    "D03": "Security and privacy",
    "D04": "Dependencies and software supply chain",
    "D05": "Data architecture and integrity",
    "D06": "Testing and quality assurance",
    "D07": "CI/CD and developer experience",
    "D08": "Infrastructure and configuration",
    "D09": "Observability and operations",
    "D10": "Performance, scalability, and resilience",
    "D11": "Documentation and engineering readiness",
}


@dataclass
class Lead:
    tool: str
    rule_id: str
    message: str
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    severity_hint: str | None = None
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def fingerprint(self) -> str:
        key = self.rule_id or (self.cwe[0] if self.cwe else "")
        raw = "%s|%s|%s" % (key, self.path, self.start_line)
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RunRecord:
    tool: str
    version: str | None
    argv: list[str]
    started_at: str
    duration_s: float
    exit_code: int | None
    status: str
    raw_output: str | None = None
    reason: str | None = None
    counts: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in SCANNER_STATES:
            raise ValueError("unknown scanner state: %r" % (self.status,))

    def to_dict(self) -> dict:
        return asdict(self)
