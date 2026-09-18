"""Attack Surface and Information Disclosure Audit Module.
Conducts fast concurrent, non-destructive checks for sensitive files, robots.txt, security.txt, and CORS misconfigurations.
"""

from typing import List, Dict, Any, Tuple
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

from core.models import Finding, Severity, Category
from core.config import SENSITIVE_PATHS, DEFAULT_REQUEST_HEADERS


def _probe_path(base_url: str, item: Dict[str, str], timeout: float = 3.5) -> Tuple[Dict[str, str], int, str, str, str]:
    """Helper to probe a single path in a thread."""
    target_path = item["path"]
    url = urljoin(base_url, target_path)
    try:
        resp = requests.get(
            url,
            headers=DEFAULT_REQUEST_HEADERS,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
        content_sample = resp.text[:1024] if resp.text else ""
        content_type = resp.headers.get("content-type", "").lower()
        return item, resp.status_code, content_sample, content_type, url
    except Exception:
        return item, 0, "", "", url


def audit_attack_surface(
    base_url: str, session: requests.Session, timeout: int = 4
) -> Tuple[List[Finding], Dict[str, Any]]:
    """Audit exposed attack surface, metadata files, and CORS policies concurrently."""
    findings: List[Finding] = []
    discovered_endpoints: List[Dict[str, Any]] = []

    # 1. Fast Concurrent Sensitive Path Probes
    probe_results = []
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [
            executor.submit(_probe_path, base_url, item, min(float(timeout), 4.0))
            for item in SENSITIVE_PATHS
        ]
        for f in as_completed(futures):
            try:
                probe_results.append(f.result())
            except Exception:
                pass

    for item, status_code, content_sample, content_type, url in probe_results:
        target_path = item["path"]
        if status_code == 200:
            # Specific verification for .git/HEAD
            if target_path == "/.git/HEAD":
                if "ref: refs/" in content_sample:
                    findings.append(
                        Finding(
                            id="EXP-GIT-HEAD",
                            title="Exposed Git Repository Metadata (/.git/HEAD)",
                            category=Category.ATTACK_SURFACE,
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            description="The server exposes Git repository internals. Attackers can reconstruct the complete source code, secrets, and commit history.",
                            impact="Full source code disclosure and potential extraction of hardcoded credentials.",
                            remediation="Block public access to the '.git' directory in web server configuration or remove it from web root.",
                            evidence=f"Found: {url} | Content starts with: {content_sample[:40].strip()}",
                            compliance_tags=["OWASP A01:2021", "PCI-DSS 4.0: Req 6.5"],
                        )
                    )
                    discovered_endpoints.append({"path": target_path, "status": 200, "verified": True})
                continue

            # Specific verification for .env
            if target_path == "/.env":
                if any(key in content_sample.upper() for key in ["DB_", "SECRET", "KEY", "TOKEN", "APP_ENV", "PASSWORD"]):
                    findings.append(
                        Finding(
                            id="EXP-ENV-DISCLOSURE",
                            title="Critical Environment Secrets File Exposed (/.env)",
                            category=Category.ATTACK_SURFACE,
                            severity=Severity.CRITICAL,
                            cvss_score=10.0,
                            description="The environment configuration file (.env) is publicly accessible, leaking production database passwords and API keys.",
                            impact="Immediate total infrastructure and database compromise.",
                            remediation="Restrict web access to '.env' files immediately and rotate all exposed API credentials and database passwords.",
                            evidence=f"Found: {url}",
                            compliance_tags=["OWASP A01:2021", "PCI-DSS 4.0: Req 8.2", "HIPAA § 164.312(a)(1)"],
                        )
                    )
                    discovered_endpoints.append({"path": target_path, "status": 200, "verified": True})
                continue

            # Robots.txt check
            if target_path == "/robots.txt":
                disallowed = [
                    line.split(":", 1)[1].strip()
                    for line in content_sample.splitlines()
                    if line.lower().startswith("disallow:")
                ]
                sensitive_disallowed = [
                    d for d in disallowed
                    if any(term in d.lower() for term in ["admin", "login", "api", "backup", "secret", "internal", "config", "private"])
                ]
                if sensitive_disallowed:
                    findings.append(
                        Finding(
                            id="EXP-ROBOTS-SENSITIVE-PATHS",
                            title="Sensitive Administrative Paths Disclosed in robots.txt",
                            category=Category.ATTACK_SURFACE,
                            severity=Severity.LOW,
                            cvss_score=3.3,
                            description=f"robots.txt discloses sensitive restricted directories: {', '.join(sensitive_disallowed[:4])}",
                            impact="Aids attackers in reconnaissance by revealing confidential application endpoints.",
                            remediation="Do not rely on robots.txt for access control. Enforce proper authentication mechanisms.",
                            evidence=f"Disallowed paths: {', '.join(sensitive_disallowed[:5])}",
                            compliance_tags=["OWASP A05:2021"],
                        )
                    )
                discovered_endpoints.append({"path": target_path, "status": 200, "verified": True})
                continue

            # Generic server-status or phpinfo
            if target_path in ["/server-status", "/phpinfo.php"]:
                if "apache server status" in content_sample.lower() or "php version" in content_sample.lower():
                    findings.append(
                        Finding(
                            id=f"EXP-{target_path.replace('/', '').replace('.', '-').upper()}",
                            title=f"Sensitive Diagnostic Page Publicly Exposed ({target_path})",
                            category=Category.ATTACK_SURFACE,
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            description=f"The diagnostic endpoint '{target_path}' is accessible without authentication.",
                            impact="Exposes internal IP addresses, active client sessions, request logs, and environmental configuration.",
                            remediation=f"Disable or restrict '{target_path}' access to localhost/internal VPN only.",
                            evidence=f"Found: {url}",
                            compliance_tags=["OWASP A05:2021"],
                        )
                    )
                    discovered_endpoints.append({"path": target_path, "status": 200, "verified": True})
                continue

            # Other sensitive files (backup.zip, web.config, .DS_Store)
            if target_path in ["/backup.zip", "/web.config", "/.DS_Store"]:
                if not content_type.startswith("text/html"):
                    findings.append(
                        Finding(
                            id=f"EXP-{target_path.replace('/', '').replace('.', '-').upper()}",
                            title=f"Sensitive Backup / Config File Accessible ({target_path})",
                            category=Category.ATTACK_SURFACE,
                            severity=Severity.HIGH,
                            cvss_score=8.2,
                            description=f"The file '{target_path}' was downloaded with status 200 OK and type '{content_type}'.",
                            impact="Potential data breach or architecture leakage via backup artifacts.",
                            remediation=f"Remove '{target_path}' from the public document root.",
                            evidence=f"URL: {url} | Content-Type: {content_type}",
                            compliance_tags=["OWASP A01:2021"],
                        )
                    )
                    discovered_endpoints.append({"path": target_path, "status": 200, "verified": True})

    # 2. RFC 9116 security.txt check
    sec_txt_url = urljoin(base_url, "/.well-known/security.txt")
    has_security_txt = False
    try:
        sec_resp = session.get(sec_txt_url, headers=DEFAULT_REQUEST_HEADERS, timeout=min(float(timeout), 3.0), allow_redirects=True)
        if sec_resp.status_code == 200 and "contact:" in sec_resp.text.lower():
            has_security_txt = True
    except Exception:
        pass

    if not has_security_txt:
        findings.append(
            Finding(
                id="SURF-NO-SECURITY-TXT",
                title="Missing RFC 9116 security.txt Vulnerability Disclosure Policy",
                category=Category.ATTACK_SURFACE,
                severity=Severity.INFO,
                cvss_score=0.0,
                description="The target does not publish a '/.well-known/security.txt' file defining security contact instructions.",
                impact="Ethical security researchers may be unable to report critical security bugs securely.",
                remediation="Deploy a standard security.txt file adhering to RFC 9116 with Contact and Expires fields.",
                evidence="HTTP 404 or unreachable at /.well-known/security.txt",
                compliance_tags=["RFC 9116"],
            )
        )

    # 3. CORS Misconfiguration Audit (Origin Reflection Test)
    test_origin = "https://evil-attacker.example.com"
    try:
        cors_headers = dict(DEFAULT_REQUEST_HEADERS)
        cors_headers["Origin"] = test_origin
        cors_resp = session.get(base_url, headers=cors_headers, timeout=min(float(timeout), 3.0), allow_redirects=False)

        allow_origin = cors_resp.headers.get("access-control-allow-origin", "").strip()
        allow_cred = cors_resp.headers.get("access-control-allow-credentials", "").lower().strip()

        if allow_origin == test_origin and allow_cred == "true":
            findings.append(
                Finding(
                    id="CORS-REFLECTED-CREDENTIALS",
                    title="Critical CORS Misconfiguration: Arbitrary Origin Reflected with Credentials",
                    category=Category.ATTACK_SURFACE,
                    severity=Severity.CRITICAL,
                    cvss_score=8.8,
                    description="The server reflects arbitrary 'Origin' values in 'Access-Control-Allow-Origin' while enabling 'Access-Control-Allow-Credentials: true'.",
                    impact="Allows any malicious website to steal authenticated user sessions, cookies, and sensitive responses via JavaScript cross-origin requests.",
                    remediation="Never reflect arbitrary Origin headers when credentials are allowed. Whitelist specific trusted origins.",
                    evidence=f"Reflected: Access-Control-Allow-Origin: {allow_origin} | Credentials: {allow_cred}",
                    compliance_tags=["OWASP A01:2021", "PCI-DSS 4.0: Req 6.4"],
                )
            )
        elif allow_origin == "*" and allow_cred == "true":
            findings.append(
                Finding(
                    id="CORS-WILDCARD-CREDENTIALS",
                    title="Insecure CORS Policy: Wildcard (*) with Credentials",
                    category=Category.ATTACK_SURFACE,
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    description="Wildcard '*' Access-Control-Allow-Origin configured in conjunction with credentials.",
                    impact="Cross-origin security mechanisms may be bypassed depending on browser implementation.",
                    remediation="Specify explicit origins instead of wildcards.",
                    evidence=f"Access-Control-Allow-Origin: * | Credentials: {allow_cred}",
                    compliance_tags=["OWASP A01:2021"],
                )
            )
    except Exception:
        pass

    metadata: Dict[str, Any] = {
        "discovered_endpoints": discovered_endpoints,
        "has_security_txt": has_security_txt,
    }

    return findings, metadata
