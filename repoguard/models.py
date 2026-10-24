"""RepoGuard AI — data models.

All structured objects flowing between the scanner, patcher and UI are
Pydantic models so that every field is validated before it is used
(defensive programming: reject malformed data early).
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """CVSS-flavoured severity buckets used across the app."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Numeric weight used to compute the overall "security score".
SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 1,
}


class Language(str, Enum):
    """Languages the static scanner understands."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    UNKNOWN = "unknown"


class Finding(BaseModel):
    """A single vulnerability detected by the rule engine."""

    rule_id: str = Field(..., description="Stable rule identifier, e.g. SEC-001")
    title: str = Field(..., description="Human-readable vulnerability title")
    severity: Severity
    owasp: str = Field(..., description="OWASP Top 10 mapping")
    line_no: int = Field(..., ge=1, description="1-based line number")
    code: str = Field(..., description="The offending source line")
    description: str = Field(..., description="Why this is dangerous")
    remediation: str = Field(..., description="Static fallback fix guidance")
    confidence: Severity = Field(
        Severity.MEDIUM,
        description="How confident the heuristic is (reused severity scale)",
    )


class ScanResult(BaseModel):
    """Aggregate result of scanning one snippet/file."""

    language: Language
    total_lines: int
    findings: list[Finding] = Field(default_factory=list)
    truncated: bool = Field(
        False, description="True if the input hit the MAX_SNIPPET_CHARS guardrail"
    )

    @property
    def security_score(self) -> int:
        """0-100 score; 100 = clean. Each finding deducts by severity weight."""
        penalty = sum(SEVERITY_WEIGHT[f.severity] for f in self.findings)
        return max(0, 100 - penalty)


class PatchResult(BaseModel):
    """AI-generated remediation for one finding."""

    finding: Finding
    explanation: str = Field(..., description="Plain-text 'why + what' for the dev")
    attack_scenario: str = Field(
        "", description="Concrete attacker's exploitation story (narrative)"
    )
    patched_code: str = Field(..., description="Corrected version of the offending line")
    diff: str = Field(..., description="Unified diff (old -> new)")
    verify_steps: str = Field(
        "", description="How the developer can confirm the fix works"
    )
    engine: str = Field(..., description="Which AI engine produced this patch")
