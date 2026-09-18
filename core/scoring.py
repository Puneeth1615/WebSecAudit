"""Scoring algorithm, Letter-Grade evaluation, and Business Impact Analysis (BIA) engine."""

from typing import List, Tuple, Dict
from core.models import Finding, BIAAssessment
from core.config import SEVERITY_DEDUCTIONS, GRADE_SCALE


def calculate_score(findings: List[Finding]) -> Tuple[float, str, str]:
    """Calculate numerical security posture score (0-100) and assign letter grade."""
    score = 100.0

    # Maximum deduction caps per category to prevent minor header/cookie omissions from collapsing score
    CATEGORY_CAPS = {
        "Cookie Security & Session Hygiene": 15.0,
        "HTTP Defensive Headers": 25.0,
        "Attack Surface & Information Disclosure": 20.0,
        "Tech Stack & Vulnerability Exposure": 25.0,
        "SSL/TLS & Transport Security": 30.0,
    }

    category_deductions: Dict[str, float] = {}

    for finding in findings:
        cat_key = finding.category.value if hasattr(finding.category, 'value') else str(finding.category)
        sev_key = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        deduction = SEVERITY_DEDUCTIONS.get(sev_key, 0.0)

        # Critical findings are high-risk and always deduct full severity points without capping
        if sev_key.upper() == "CRITICAL":
            score -= deduction
        else:
            category_deductions[cat_key] = category_deductions.get(cat_key, 0.0) + deduction

    total_deduction = 0.0
    for cat_key, raw_ded in category_deductions.items():
        cap = CATEGORY_CAPS.get(cat_key, None)
        if cap is not None:
            total_deduction += min(raw_ded, cap)
        else:
            total_deduction += raw_ded

    score -= total_deduction
    score = max(0.0, min(100.0, round(score, 1)))

    assigned_grade = "F"
    assigned_desc = "Failing security posture with critical vulnerabilities."

    for threshold, grade, desc in GRADE_SCALE:
        if score >= threshold:
            assigned_grade = grade
            assigned_desc = desc
            break

    return score, assigned_grade, assigned_desc


def compute_bia_assessment(
    findings: List[Finding], target_url: str, score: float, grade: str
) -> BIAAssessment:
    """Evaluate business risk across CIA triad, regulatory exposure, and financial impact."""
    crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity == "LOW")

    # Confidentiality Risk
    conf_risk = "Low"
    if crit_count > 0 or any("credential" in f.title.lower() or ".env" in f.title.lower() or "git" in f.title.lower() for f in findings):
        conf_risk = "Critical"
    elif high_count > 0 or any("cookie" in f.title.lower() and "httponly" in f.description.lower() for f in findings):
        conf_risk = "High"
    elif med_count > 0:
        conf_risk = "Medium"

    # Integrity Risk
    integ_risk = "Low"
    if any("cors" in f.title.lower() or "csp" in f.title.lower() or "frame" in f.title.lower() for f in findings):
        integ_risk = "High" if crit_count + high_count > 0 else "Medium"
    elif crit_count > 0:
        integ_risk = "High"

    # Availability Risk
    avail_risk = "Low"
    if any("status" in f.title.lower() or "cve" in f.category.lower() for f in findings):
        avail_risk = "Medium"
    if any("dos" in f.description.lower() or "denial" in f.description.lower() for f in findings):
        avail_risk = "High"

    # Regulatory Compliance Assessment
    regulatory = {}

    # PCI-DSS 4.0 check
    has_tls_issue = any(f.category == "SSL/TLS & Transport Security" and f.severity in ["HIGH", "CRITICAL"] for f in findings)
    has_hsts_issue = any("hsts" in f.title.lower() for f in findings)
    if has_tls_issue or has_hsts_issue:
        regulatory["PCI-DSS 4.0"] = "NON-COMPLIANT (Req 4.1: Strong Cryptography & Req 6.4: Web Security)"
    elif any(f.category == "Cookie Security & Session Hygiene" for f in findings):
        regulatory["PCI-DSS 4.0"] = "AT-RISK (Req 8.2: Authentication and Session Security)"
    else:
        regulatory["PCI-DSS 4.0"] = "COMPLIANT (Baseline controls satisfied)"

    # HIPAA Security Rule
    if conf_risk in ["Critical", "High"] or has_tls_issue:
        regulatory["HIPAA Security Rule"] = "AT-RISK (Section 164.312(e)(1) Transmission Security & ePHI Protection)"
    else:
        regulatory["HIPAA Security Rule"] = "ADEQUATE (Transmission standards met)"

    # GDPR Article 32
    if crit_count > 0 or high_count >= 2:
        regulatory["GDPR Art. 32"] = "NON-COMPLIANT (Inadequate Technical & Organizational Measures)"
    elif med_count >= 3:
        regulatory["GDPR Art. 32"] = "AT-RISK (Data Protection Safeguards Sub-Optimal)"
    else:
        regulatory["GDPR Art. 32"] = "COMPLIANT (Demonstrates reasonable technical hygiene)"

    # Financial & Reputational Risk Rating
    if crit_count > 0 or score < 60.0:
        fin_impact = "Critical - High probability of data breach fines and remediation costs"
        rep_risk = "Critical - Severe brand reputation damage if exposed publicly"
    elif high_count > 0 or score < 75.0:
        fin_impact = "Elevated - Vulnerable to targeted attacks and regulatory scrutiny"
        rep_risk = "High - Potential customer churn and security advisory disclosures"
    elif med_count > 2 or score < 85.0:
        fin_impact = "Moderate - Maintenance and security patching overhead required"
        rep_risk = "Medium - May raise concerns during enterprise B2B vendor security audits"
    else:
        fin_impact = "Low - Standard security operational maintenance required"
        rep_risk = "Low - Posture adheres to modern industry baseline standards"

    # Executive Summary text
    exec_summary = (
        f"The security posture assessment for '{target_url}' yielded an overall score of {score}/100 "
        f"(Grade: {grade}). The audit identified {crit_count} Critical, {high_count} High, {med_count} Medium, "
        f"and {low_count} Low severity findings. "
    )
    if crit_count > 0 or high_count > 0:
        exec_summary += (
            "Immediate remediation is recommended. The presence of high-severity vulnerabilities exposes "
            "the organization to elevated regulatory risk under frameworks like PCI-DSS and GDPR, as well "
            "as potential session hijacking, data leakage, or infrastructure compromise."
        )
    else:
        exec_summary += (
            "The target displays solid baseline defensive controls. Addressing minor header omissions "
            "and maintaining regular patch management will uphold defense-in-depth posture."
        )

    return BIAAssessment(
        confidentiality_risk=conf_risk,
        integrity_risk=integ_risk,
        availability_risk=avail_risk,
        regulatory_exposure=regulatory,
        financial_impact_rating=fin_impact,
        reputational_risk_rating=rep_risk,
        executive_summary=exec_summary,
    )
