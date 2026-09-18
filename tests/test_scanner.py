"""Unit tests for WebSecAudit core logic, modules, scoring, and reporters."""

import os
import unittest
from unittest.mock import MagicMock
import requests

from core.models import Finding, Severity, Category, AuditResult
from core.scoring import calculate_score, compute_bia_assessment
from modules.headers_audit import audit_headers
from modules.cookies_audit import audit_cookies
from reporters.json_reporter import export_json_report
from reporters.pdf_reporter import generate_pdf_report


class TestWebSecAudit(unittest.TestCase):

    def test_scoring_deductions_and_grades(self):
        """Verify accurate score calculation and grade categorization."""
        # 1. Zero findings = 100 A+
        score, grade, _ = calculate_score([])
        self.assertEqual(score, 100.0)
        self.assertEqual(grade, "A+")

        # 2. One High (-15) + One Medium (-7) = 78 C
        findings = [
            Finding("1", "High Vuln", Category.SECURITY_HEADERS, Severity.HIGH, 7.5, "desc", "imp", "rem"),
            Finding("2", "Med Vuln", Category.SECURITY_HEADERS, Severity.MEDIUM, 5.0, "desc", "imp", "rem"),
        ]
        score, grade, _ = calculate_score(findings)
        self.assertEqual(score, 78.0)
        self.assertEqual(grade, "C")

        # 3. Multiple critical findings should bottom out at 0.0 with F
        crit_findings = [
            Finding(str(i), f"Crit {i}", Category.ATTACK_SURFACE, Severity.CRITICAL, 9.8, "desc", "imp", "rem")
            for i in range(5)
        ]
        score, grade, _ = calculate_score(crit_findings)
        self.assertEqual(score, 0.0)
        self.assertEqual(grade, "F")

    def test_bia_assessment_logic(self):
        """Verify Business Impact Analysis vectors and compliance triggers."""
        findings = [
            Finding(
                id="EXP-GIT-HEAD",
                title="Exposed Git Metadata",
                category=Category.ATTACK_SURFACE,
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description="Git metadata leaked",
                impact="Code disclosure",
                remediation="Remove .git",
            ),
            Finding(
                id="HDR-HSTS-MISSING",
                title="Missing HSTS",
                category=Category.SECURITY_HEADERS,
                severity=Severity.HIGH,
                cvss_score=7.4,
                description="No HSTS",
                impact="SSL strip",
                remediation="Add HSTS",
            ),
        ]
        score, grade, _ = calculate_score(findings)
        bia = compute_bia_assessment(findings, "https://example.com", score, grade)

        self.assertEqual(bia.confidentiality_risk, "Critical")
        self.assertIn("PCI-DSS 4.0", bia.regulatory_exposure)
        self.assertIn("NON-COMPLIANT", bia.regulatory_exposure["PCI-DSS 4.0"])
        self.assertIn("GDPR Art. 32", bia.regulatory_exposure)

    def test_headers_audit_evaluations(self):
        """Verify headers auditing flags missing and insecure headers."""
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        # Simulated response missing HSTS, CSP, and XFO, but with Server banner
        mock_response.headers = {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "Content-Type": "text/html",
        }

        findings, metadata = audit_headers(mock_response)
        finding_ids = [f.id for f in findings]

        self.assertIn("HDR-HSTS-MISSING", finding_ids)
        self.assertIn("HDR-CSP-MISSING", finding_ids)
        self.assertIn("HDR-XFO-MISSING", finding_ids)
        self.assertIn("LEAK-SERVER", finding_ids)
        self.assertIn("Strict-Transport-Security", metadata["defensive_headers_missing"])

    def test_cookies_audit_flags(self):
        """Verify cookie auditor identifies missing Secure and HttpOnly flags."""
        mock_response = MagicMock(spec=requests.Response)
        mock_response.headers = {
            "set-cookie": "session_token=abc123456789; Path=/"
        }
        mock_response.raw = MagicMock()
        mock_response.raw.headers = MagicMock()
        mock_response.raw.headers.getlist.return_value = ["session_token=abc123456789; Path=/"]

        findings, metadata = audit_cookies(mock_response, is_https=True)
        finding_ids = [f.id for f in findings]

        self.assertTrue(any("SECURE" in fid for fid in finding_ids))
        self.assertTrue(any("HTTPONLY" in fid for fid in finding_ids))
        self.assertTrue(any("SAMESITE" in fid for fid in finding_ids))
        self.assertEqual(metadata["cookies_detected_count"], 1)

    def test_pdf_and_json_report_generation(self):
        """Verify PDF and JSON reporters execute cleanly and produce valid deliverables."""
        findings = [
            Finding(
                id="HDR-CSP-MISSING",
                title="Missing Content-Security-Policy",
                category=Category.SECURITY_HEADERS,
                severity=Severity.MEDIUM,
                cvss_score=6.1,
                description="No CSP found on response.",
                impact="XSS vulnerability elevated.",
                remediation="Deploy CSP default-src 'self'.",
                evidence="Header absent",
                compliance_tags=["OWASP A03:2021", "PCI-DSS 4.0"],
            )
        ]
        score, grade, desc = calculate_score(findings)
        bia = compute_bia_assessment(findings, "https://test.example.com", score, grade)

        result = AuditResult(
            target_url="https://test.example.com",
            ip_address="93.184.216.34",
            scan_timestamp="2026-09-14 12:00:00",
            scan_duration_seconds=2.45,
            score=score,
            grade=grade,
            grade_description=desc,
            findings=findings,
            metadata={
                "ssl": {
                    "tls_version": "TLSv1.3",
                    "cipher_suite": "TLS_AES_256_GCM_SHA384",
                    "cert_expiry": "2027-01-01 00:00:00 UTC",
                    "days_until_expiry": 108,
                    "cert_issuer": "CN=Let's Encrypt Authority",
                    "key_type": "RSA",
                    "key_size": 2048,
                },
                "headers": {
                    "defensive_headers_present": ["X-Content-Type-Options"],
                    "defensive_headers_missing": ["Content-Security-Policy", "Strict-Transport-Security"],
                },
                "cookies": {"audited_cookies": []},
                "fingerprint": {"server_banner": "nginx/1.24.0"},
            },
            bia=bia,
        )

        # Test JSON Export
        json_output_path = "test_output.json"
        json_str = export_json_report(result, file_path=json_output_path)
        self.assertIn('"score": 93.0', json_str)
        self.assertTrue(os.path.exists(json_output_path))
        os.remove(json_output_path)

        # Test PDF Export
        pdf_output_path = "test_output.pdf"
        generate_pdf_report(result, output_path=pdf_output_path)
        self.assertTrue(os.path.exists(pdf_output_path))
        self.assertGreater(os.path.getsize(pdf_output_path), 5000)
        os.remove(pdf_output_path)


if __name__ == "__main__":
    unittest.main()
