"""Core Audit Engine orchestrator for WebSecAudit."""

import time
import socket
import datetime
from urllib.parse import urlparse
from typing import Optional, Callable
import requests
import urllib3

# Suppress unverified HTTPS warnings for scanner inspections
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.models import AuditResult, Finding, Severity, Category
from core.config import DEFAULT_REQUEST_HEADERS, DEFAULT_TIMEOUT, SOCKET_TIMEOUT
from core.scoring import calculate_score, compute_bia_assessment
from modules.ssl_audit import audit_ssl
from modules.headers_audit import audit_headers
from modules.cookies_audit import audit_cookies
from modules.fingerprint_audit import audit_fingerprint
from modules.surface_audit import audit_attack_surface


class AuditEngine:
    """Orchestrates multi-pillar web application security assessment."""

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        check_online_cve: bool = True,
        progress_callback: Optional[Callable[[str, str], None]] = None,
    ):
        self.timeout = timeout
        self.check_online_cve = check_online_cve
        self.progress_callback = progress_callback or (lambda step, status: None)
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_REQUEST_HEADERS)

    def run_audit(self, raw_target: str) -> AuditResult:
        """Run complete security audit against the target URL."""
        start_time = time.time()

        # 1. Normalize Target URL
        target_url = raw_target.strip()
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"

        parsed = urlparse(target_url)
        hostname = parsed.hostname or raw_target
        is_https = parsed.scheme == "https"
        port = parsed.port or (443 if is_https else 80)
        base_url = f"{parsed.scheme}://{hostname}{f':{port}' if parsed.port else ''}"

        # 2. Resolve IP Address
        ip_address = None
        try:
            ip_address = socket.gethostbyname(hostname)
        except socket.gaierror:
            pass

        all_findings: list[Finding] = []
        aggregated_metadata: dict = {
            "hostname": hostname,
            "port": port,
            "scheme": parsed.scheme,
            "ip_address": ip_address,
        }

        # 3. Module 1: SSL/TLS Transport Audit
        if is_https:
            self.progress_callback("SSL/TLS Transport Audit", "Running socket & certificate checks...")
            ssl_findings, ssl_meta = audit_ssl(hostname, port, timeout=SOCKET_TIMEOUT)
            all_findings.extend(ssl_findings)
            aggregated_metadata["ssl"] = ssl_meta
        else:
            all_findings.append(
                Finding(
                    id="TLS-HTTP-INSECURE",
                    title="Insecure Plaintext HTTP Protocol in Use",
                    category=Category.TRANSPORT_SECURITY,
                    severity=Severity.CRITICAL,
                    cvss_score=9.0,
                    description="The target communicates over unencrypted HTTP (Port 80).",
                    impact="All credentials, cookies, and sensitive data are transmitted in cleartext and vulnerable to interception.",
                    remediation="Deploy a trusted TLS certificate and redirect all HTTP traffic to HTTPS.",
                    evidence=f"Target URL uses scheme: {parsed.scheme}",
                    compliance_tags=["PCI-DSS 4.0: Req 4.1", "HIPAA § 164.312(e)(1)"],
                )
            )

        # 4. Fetch Primary Web Response
        self.progress_callback("HTTP Connection", f"Requesting {target_url}...")
        primary_response = None
        try:
            primary_response = self.session.get(
                target_url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,  # Allow inspection of target regardless of cert errors
            )
            aggregated_metadata["http_status"] = primary_response.status_code
            aggregated_metadata["effective_url"] = primary_response.url
        except requests.RequestException as e:
            all_findings.append(
                Finding(
                    id="CONN-HTTP-FAILED",
                    title="HTTPS Web Connection Attempt Failed",
                    category=Category.ATTACK_SURFACE,
                    severity=Severity.HIGH,
                    cvss_score=7.0,
                    description=f"Could not retrieve web response from {target_url}. Error: {str(e)}",
                    impact="Web application posture assessment over HTTPS limited.",
                    remediation="Verify target is online, DNS resolves, and firewall allows ingress HTTP/HTTPS.",
                    evidence=str(e),
                    compliance_tags=["Operational Hygiene"],
                )
            )

        # Fallback to HTTP (port 80) if HTTPS failed, to permit auditing remaining web posture
        if not primary_response and is_https:
            fallback_url = f"http://{hostname}"
            try:
                self.progress_callback("HTTP Fallback", f"Testing plaintext HTTP fallback on {fallback_url}...")
                fallback_resp = self.session.get(fallback_url, timeout=self.timeout, allow_redirects=True)
                primary_response = fallback_resp
                base_url = fallback_url
                aggregated_metadata["http_status"] = primary_response.status_code
                aggregated_metadata["effective_url"] = primary_response.url
            except Exception:
                pass

        # 5. Module 2: Defensive HTTP Headers Audit
        if primary_response:
            self.progress_callback("Defensive Headers", "Evaluating HSTS, CSP, and security policies...")
            hdr_findings, hdr_meta = audit_headers(primary_response)
            all_findings.extend(hdr_findings)
            aggregated_metadata["headers"] = hdr_meta

            # 6. Module 3: Cookie Security & Session Hygiene
            self.progress_callback("Cookie Hygiene", "Inspecting Set-Cookie flags and attributes...")
            cookie_findings, cookie_meta = audit_cookies(primary_response, is_https=is_https)
            all_findings.extend(cookie_findings)
            aggregated_metadata["cookies"] = cookie_meta

            # 7. Module 4: Technology Stack & CVE Mapping
            self.progress_callback("Tech Stack Fingerprint", "Analyzing banners, DOM markers, and CVE databases...")
            fp_findings, fp_meta = audit_fingerprint(primary_response, check_online_cve=self.check_online_cve)
            all_findings.extend(fp_findings)
            aggregated_metadata["fingerprint"] = fp_meta

        # 8. Module 5: Attack Surface & Information Exposure
        self.progress_callback("Attack Surface Discovery", "Testing high-risk endpoints, robots.txt, and CORS...")
        surf_findings, surf_meta = audit_attack_surface(base_url, self.session, timeout=self.timeout)
        all_findings.extend(surf_findings)
        aggregated_metadata["surface"] = surf_meta

        # 9. Calculate Scoring & BIA
        self.progress_callback("Assessment Synthesis", "Computing CVSS alignment, posture grade, and BIA...")
        score, grade, grade_desc = calculate_score(all_findings)
        bia = compute_bia_assessment(all_findings, target_url, score, grade)

        duration = round(time.time() - start_time, 2)
        scan_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        result = AuditResult(
            target_url=target_url,
            ip_address=ip_address,
            scan_timestamp=scan_time_str,
            scan_duration_seconds=duration,
            score=score,
            grade=grade,
            grade_description=grade_desc,
            findings=all_findings,
            metadata=aggregated_metadata,
            bia=bia,
        )

        self.progress_callback("Complete", f"Audit finished in {duration}s. Posture Score: {score}/100 ({grade})")
        return result
