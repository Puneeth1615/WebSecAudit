"""Data models for WebSecAudit findings, scores, and BIA assessment."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    TRANSPORT_SECURITY = "SSL/TLS & Transport Security"
    SECURITY_HEADERS = "HTTP Defensive Headers"
    COOKIE_HYGIENE = "Cookie Security & Session Hygiene"
    TECH_STACK_CVE = "Tech Stack & Vulnerability Exposure"
    ATTACK_SURFACE = "Attack Surface & Information Disclosure"


@dataclass
class Finding:
    """Represents a specific security audit finding."""
    id: str
    title: str
    category: str
    severity: str
    cvss_score: float
    description: str
    impact: str
    remediation: str
    evidence: Optional[str] = None
    compliance_tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BIAAssessment:
    """Represents the Business Impact Analysis calculated for the target."""
    confidentiality_risk: str
    integrity_risk: str
    availability_risk: str
    regulatory_exposure: Dict[str, str] = field(default_factory=dict)
    financial_impact_rating: str = "Low"
    reputational_risk_rating: str = "Low"
    executive_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditResult:
    """Aggregated output of a comprehensive security audit."""
    target_url: str
    ip_address: Optional[str]
    scan_timestamp: str
    scan_duration_seconds: float
    score: float = 100.0
    grade: str = "A+"
    grade_description: str = ""
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    bia: Optional[BIAAssessment] = None

    def count_by_severity(self) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity_breakdown"] = self.count_by_severity()
        return data
