"""Technology Stack Fingerprinting and Known Vulnerability (CVE) Mapping Module.
Combines passive banner/DOM inspection, curated signature matching, and the OSV.dev API.
"""

import re
from typing import List, Dict, Any, Tuple
import requests

from core.models import Finding, Severity, Category
from core.config import OSV_QUERY_ENDPOINT, DEFAULT_TIMEOUT

# Curated high-impact known vulnerabilities for common web server banners (fallback/offline engine)
KNOWN_SIGNATURE_CVES = [
    {
        "pattern": r"apache/(?:2\.4\.49|2\.4\.50)",
        "product": "Apache HTTP Server",
        "cve": "CVE-2021-41773 / CVE-2021-42013",
        "severity": Severity.CRITICAL,
        "cvss": 9.8,
        "title": "Apache Path Traversal and Remote Code Execution",
        "remediation": "Immediately upgrade Apache HTTP Server to version 2.4.51 or later.",
    },
    {
        "pattern": r"apache/2\.4\.(?:[0-9]|[1-3][0-9]|4[0-8])\b",
        "product": "Apache HTTP Server",
        "cve": "CVE-2021-40438",
        "severity": Severity.HIGH,
        "cvss": 8.6,
        "title": "Apache HTTP Server mod_proxy SSRF Vulnerability",
        "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or later.",
    },
    {
        "pattern": r"nginx/(?:0\..*|1\.[0-9]\..*|1\.1[0-7]\..*|1\.18\.0)",
        "product": "Nginx",
        "cve": "CVE-2021-23017",
        "severity": Severity.HIGH,
        "cvss": 7.7,
        "title": "Nginx 1-byte Memory Overwrite / DoS in DNS Resolver",
        "remediation": "Upgrade Nginx to the latest stable release (1.20+ or 1.22+).",
    },
    {
        "pattern": r"php/(?:5\..*|7\.[0-3]\..*)",
        "product": "PHP Engine",
        "cve": "End-of-Life PHP Runtime",
        "severity": Severity.HIGH,
        "cvss": 8.0,
        "title": "Unsupported & End-of-Life PHP Version Detected",
        "remediation": "Upgrade PHP to an actively maintained branch (8.2 or 8.3+).",
    },
    {
        "pattern": r"wordpress/(?:[1-5]\..*|6\.[0-1]\b)",
        "product": "WordPress CMS",
        "cve": "Outdated WordPress Core",
        "severity": Severity.HIGH,
        "cvss": 7.8,
        "title": "Outdated WordPress CMS Core Version",
        "remediation": "Update WordPress to the latest release and audit installed plugins.",
    },
]


def audit_fingerprint(response: requests.Response, check_online_cve: bool = True) -> Tuple[List[Finding], Dict[str, Any]]:
    """Passively detect technologies, frameworks, and correlate with known CVEs."""
    findings: List[Finding] = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    html_text = response.text if response.text else ""

    detected_tech: List[Dict[str, str]] = []
    server_banner = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")

    # 1. Inspect Server header
    if server_banner:
        detected_tech.append({"type": "Web Server", "name": server_banner})

    # 2. Inspect X-Powered-By
    if powered_by:
        detected_tech.append({"type": "Runtime / Framework", "name": powered_by})

    # 3. DOM & Meta Inspection
    # Meta generator
    gen_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', html_text, re.IGNORECASE)
    if not gen_match:
        gen_match = re.search(r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']generator["\']', html_text, re.IGNORECASE)
    if gen_match:
        generator_val = gen_match.group(1).strip()
        detected_tech.append({"type": "CMS / Generator", "name": generator_val})

    # Script & Framework Heuristics
    dom_heuristics = [
        ("WordPress", r"/wp-content/|/wp-includes/"),
        ("Joomla", r"Joomla!|/templates/[^\"'>]+/"),
        ("Drupal", r"Drupal|sites/default/files"),
        ("React", r"react\.production\.min\.js|__NEXT_DATA__|data-reactroot"),
        ("Vue.js", r"vue\.runtime|data-v-[0-9a-fA-F]+"),
        ("Angular", r"ng-version|ng-app"),
        ("jQuery", r"jquery(?:-|\.)([0-9\.]+)?(?:\.min)?\.js"),
        ("Bootstrap", r"bootstrap(?:-|\.)([0-9\.]+)?(?:\.min)?\.(?:js|css)"),
        ("Laravel", r"laravel_session|XSRF-TOKEN"),
        ("Django", r"csrfmiddlewaretoken"),
    ]

    for tech_name, regex in dom_heuristics:
        m = re.search(regex, html_text, re.IGNORECASE)
        if m:
            version_str = m.group(1) if m.groups() and m.group(1) else ""
            detected_tech.append({
                "type": "Client/Frontend Framework" if tech_name in ["React", "Vue.js", "Angular", "jQuery", "Bootstrap"] else "Backend/CMS Framework",
                "name": f"{tech_name} {version_str}".strip()
            })

    # 4. Correlate with Known Curated Signatures
    full_banner_string = f"{server_banner} {powered_by}".lower()
    for sig in KNOWN_SIGNATURE_CVES:
        if re.search(sig["pattern"], full_banner_string):
            findings.append(
                Finding(
                    id=f"CVE-{sig['cve'].replace(' ', '-').replace('/', '-')}",
                    title=f"Known Vulnerability Detected: {sig['title']} ({sig['cve']})",
                    category=Category.TECH_STACK_CVE,
                    severity=sig["severity"],
                    cvss_score=sig["cvss"],
                    description=f"The detected server banner matches signature for {sig['product']} with public security advisory {sig['cve']}.",
                    impact="Potential system compromise, remote code execution, or unauthorized sensitive data access depending on patch level.",
                    remediation=sig["remediation"],
                    evidence=f"Banner match: '{server_banner or powered_by}'",
                    compliance_tags=["OWASP A06:2021", "NIST SP 800-40r4", "PCI-DSS 4.0: Req 6.2"],
                )
            )

    # 5. Optional Online OSV.dev query for identified package components
    if check_online_cve:
        for tech in detected_tech:
            # Check if there is a discernible name and version
            parts = tech["name"].split("/")
            if len(parts) == 2 and parts[1].replace(".", "").isdigit():
                pkg_name = parts[0].strip()
                pkg_version = parts[1].strip()
                try:
                    query_payload = {
                        "version": pkg_version,
                        "package": {"name": pkg_name.lower()}
                    }
                    resp = requests.post(OSV_QUERY_ENDPOINT, json=query_payload, timeout=3)
                    if resp.status_code == 200:
                        data = resp.json()
                        vulns = data.get("vulns", [])
                        for vuln in vulns[:2]:  # Limit top 2 to prevent report flooding
                            vuln_id = vuln.get("id", "OSV-VULN")
                            summary = vuln.get("summary", "Public vulnerability found in OSV database.")
                            findings.append(
                                Finding(
                                    id=f"OSV-{vuln_id}",
                                    title=f"OSV Advisory for {pkg_name}: {vuln_id}",
                                    category=Category.TECH_STACK_CVE,
                                    severity=Severity.HIGH,
                                    cvss_score=7.5,
                                    description=f"{summary} (Affecting {pkg_name} version {pkg_version})",
                                    impact="Exploitable vulnerability documented in open source vulnerability records.",
                                    remediation=f"Upgrade {pkg_name} beyond affected range specified in {vuln_id}.",
                                    evidence=f"Queried package {pkg_name}@{pkg_version}",
                                    compliance_tags=["OWASP A06:2021"],
                                )
                            )
                except Exception:
                    # Online query failed or timed out; silent fallback
                    pass

    metadata: Dict[str, Any] = {
        "server_banner": server_banner or "Hidden / Suppressed",
        "powered_by": powered_by or "None",
        "detected_technologies": detected_tech,
    }

    return findings, metadata
