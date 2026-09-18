"""HTTP Defensive Headers and Information Disclosure Audit Module.
Evaluates modern defensive headers (HSTS, CSP, X-Frame-Options, etc.) and leakage banners.
"""

from typing import List, Dict, Any, Tuple
import requests

from core.models import Finding, Severity, Category


def audit_headers(response: requests.Response) -> Tuple[List[Finding], Dict[str, Any]]:
    """Audit HTTP response headers against security best practices."""
    findings: List[Finding] = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    raw_headers = dict(response.headers)

    metadata: Dict[str, Any] = {
        "status_code": response.status_code,
        "inspected_headers_count": len(headers),
        "defensive_headers_present": [],
        "defensive_headers_missing": [],
        "raw_headers": raw_headers,
    }

    # 1. Strict-Transport-Security (HSTS)
    hsts = headers.get("strict-transport-security")
    if not hsts:
        findings.append(
            Finding(
                id="HDR-HSTS-MISSING",
                title="Missing HTTP Strict-Transport-Security (HSTS) Header",
                category=Category.SECURITY_HEADERS,
                severity=Severity.HIGH,
                cvss_score=7.4,
                description="The server does not enforce HTTPS via the Strict-Transport-Security header.",
                impact="Vulnerable to SSL-stripping and man-in-the-middle downgrade attacks on insecure Wi-Fi/networks.",
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
                evidence="Header 'Strict-Transport-Security' is absent.",
                compliance_tags=["PCI-DSS 4.0: Req 6.4", "OWASP A05:2021", "NIST SP 800-52r2"],
            )
        )
        metadata["defensive_headers_missing"].append("Strict-Transport-Security")
    else:
        metadata["defensive_headers_present"].append("Strict-Transport-Security")
        hsts_lower = hsts.lower()
        if "max-age" in hsts_lower:
            try:
                parts = [p.strip() for p in hsts_lower.split(";")]
                for p in parts:
                    if p.startswith("max-age"):
                        age = int(p.split("=")[1])
                        if age < 15768000:  # less than ~6 months
                            findings.append(
                                Finding(
                                    id="HDR-HSTS-SHORT-MAXAGE",
                                    title=f"Short HSTS max-age Duration ({age} seconds)",
                                    category=Category.SECURITY_HEADERS,
                                    severity=Severity.LOW,
                                    cvss_score=3.1,
                                    description=f"The HSTS max-age is set to {age}s. Industry baseline recommends at least 31536000 seconds (1 year).",
                                    impact="Users who do not visit frequently may become vulnerable to downgrade attacks upon expiry.",
                                    remediation="Increase HSTS max-age to at least 31536000 (1 year).",
                                    evidence=f"Strict-Transport-Security: {hsts}",
                                    compliance_tags=["OWASP A05:2021"],
                                )
                            )
            except Exception:
                pass
        if "includesubdomains" not in hsts_lower:
            findings.append(
                Finding(
                    id="HDR-HSTS-NO-SUBDOMAINS",
                    title="HSTS Missing 'includeSubDomains' Directive",
                    category=Category.SECURITY_HEADERS,
                    severity=Severity.LOW,
                    cvss_score=2.8,
                    description="The HSTS policy does not cover subdomains.",
                    impact="Subdomains remain vulnerable to protocol downgrade attacks.",
                    remediation="Add 'includeSubDomains' directive to the HSTS header.",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    compliance_tags=["OWASP A05:2021"],
                )
            )

    # 2. Content-Security-Policy (CSP)
    csp = headers.get("content-security-policy")
    if not csp:
        findings.append(
            Finding(
                id="HDR-CSP-MISSING",
                title="Missing Content-Security-Policy (CSP) Header",
                category=Category.SECURITY_HEADERS,
                severity=Severity.MEDIUM,
                cvss_score=6.1,
                description="No Content-Security-Policy header was returned by the server.",
                impact="Lack of CSP drastically increases vulnerability to Cross-Site Scripting (XSS), malicious script injection, and clickjacking.",
                remediation="Define and deploy a strict CSP restricting script, object, and style sources (e.g. default-src 'self').",
                evidence="Header 'Content-Security-Policy' is absent.",
                compliance_tags=["OWASP A03:2021", "PCI-DSS 4.0: Req 6.4"],
            )
        )
        metadata["defensive_headers_missing"].append("Content-Security-Policy")
    else:
        metadata["defensive_headers_present"].append("Content-Security-Policy")
        csp_lower = csp.lower()
        if "'unsafe-inline'" in csp_lower:
            findings.append(
                Finding(
                    id="HDR-CSP-UNSAFE-INLINE",
                    title="Content-Security-Policy Permits 'unsafe-inline'",
                    category=Category.SECURITY_HEADERS,
                    severity=Severity.MEDIUM,
                    cvss_score=5.5,
                    description="The CSP policy allows 'unsafe-inline' execution of scripts or styles.",
                    impact="Substantially degrades CSP defense against Reflected and Stored Cross-Site Scripting (XSS).",
                    remediation="Remove 'unsafe-inline' and implement cryptographic nonces or SHA-256 hashes for inline assets.",
                    evidence=f"CSP fragment: {csp[:120]}...",
                    compliance_tags=["OWASP A03:2021"],
                )
            )
        if "'unsafe-eval'" in csp_lower:
            findings.append(
                Finding(
                    id="HDR-CSP-UNSAFE-EVAL",
                    title="Content-Security-Policy Permits 'unsafe-eval'",
                    category=Category.SECURITY_HEADERS,
                    severity=Severity.LOW,
                    cvss_score=3.8,
                    description="The CSP policy allows 'unsafe-eval' which permits dynamic JavaScript string evaluation.",
                    impact="Enables DOM-based code execution if untrusted input reaches eval-like functions.",
                    remediation="Refactor code to eliminate eval(), Function(), and setTimeout string executions.",
                    evidence=f"CSP: {csp[:120]}...",
                    compliance_tags=["OWASP A03:2021"],
                )
            )
        if " *" in csp_lower or "*;" in csp_lower or csp_lower.endswith("*"):
            findings.append(
                Finding(
                    id="HDR-CSP-WILDCARD",
                    title="Content-Security-Policy Uses Wildcard (*) Source",
                    category=Category.SECURITY_HEADERS,
                    severity=Severity.MEDIUM,
                    cvss_score=5.0,
                    description="Wildcard '*' directive detected in CSP, allowing resources from any external domain.",
                    impact="Negates domain-whitelisting protections against data exfiltration and rogue scripts.",
                    remediation="Specify explicit trusted domains instead of wildcards.",
                    evidence=f"CSP: {csp[:120]}...",
                    compliance_tags=["OWASP A03:2021"],
                )
            )

    # 3. X-Frame-Options (Clickjacking)
    xfo = headers.get("x-frame-options")
    csp_has_frame_ancestors = csp and "frame-ancestors" in csp.lower()
    if not xfo and not csp_has_frame_ancestors:
        findings.append(
            Finding(
                id="HDR-XFO-MISSING",
                title="Missing X-Frame-Options / Clickjacking Protection",
                category=Category.SECURITY_HEADERS,
                severity=Severity.MEDIUM,
                cvss_score=5.4,
                description="The application does not provide clickjacking protection via X-Frame-Options or CSP 'frame-ancestors'.",
                impact="Attackers can embed the target page in a hidden iframe on a malicious site to trick users into unintended actions.",
                remediation="Configure 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use CSP 'frame-ancestors 'self''.",
                evidence="Neither 'X-Frame-Options' nor 'frame-ancestors' present.",
                compliance_tags=["OWASP A05:2021", "WASC-15"],
            )
        )
        metadata["defensive_headers_missing"].append("X-Frame-Options")
    else:
        metadata["defensive_headers_present"].append("X-Frame-Options")
        if xfo and xfo.upper() not in ["DENY", "SAMEORIGIN"]:
            findings.append(
                Finding(
                    id="HDR-XFO-INVALID",
                    title=f"Non-Standard or Insecure X-Frame-Options Value: '{xfo}'",
                    category=Category.SECURITY_HEADERS,
                    severity=Severity.LOW,
                    cvss_score=3.5,
                    description=f"Value '{xfo}' may not be supported consistently across modern browsers (e.g. ALLOW-FROM is obsolete).",
                    impact="Clickjacking protection may fail silently in modern browsers.",
                    remediation="Use 'DENY' or 'SAMEORIGIN', or migrate to CSP frame-ancestors.",
                    evidence=f"X-Frame-Options: {xfo}",
                    compliance_tags=["OWASP A05:2021"],
                )
            )

    # 4. X-Content-Type-Options (MIME Sniffing)
    xcto = headers.get("x-content-type-options")
    if not xcto:
        findings.append(
            Finding(
                id="HDR-XCTO-MISSING",
                title="Missing X-Content-Type-Options Header",
                category=Category.SECURITY_HEADERS,
                severity=Severity.LOW,
                cvss_score=3.7,
                description="The 'X-Content-Type-Options: nosniff' header is missing from server responses.",
                impact="Older or legacy browsers may sniff the response MIME type, potentially executing uploaded text or images as HTML/JavaScript.",
                remediation="Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
                evidence="Header 'X-Content-Type-Options' is absent.",
                compliance_tags=["OWASP A05:2021"],
            )
        )
        metadata["defensive_headers_missing"].append("X-Content-Type-Options")
    elif xcto.lower().strip() != "nosniff":
        findings.append(
            Finding(
                id="HDR-XCTO-INVALID",
                title=f"Invalid X-Content-Type-Options Value: '{xcto}'",
                category=Category.SECURITY_HEADERS,
                severity=Severity.LOW,
                cvss_score=3.0,
                description=f"The value is set to '{xcto}' instead of 'nosniff'.",
                impact="MIME-sniffing protections are bypassed.",
                remediation="Set 'X-Content-Type-Options: nosniff'.",
                evidence=f"X-Content-Type-Options: {xcto}",
                compliance_tags=["OWASP A05:2021"],
            )
        )
    else:
        metadata["defensive_headers_present"].append("X-Content-Type-Options")

    # 5. Referrer-Policy
    rp = headers.get("referrer-policy")
    if not rp:
        findings.append(
            Finding(
                id="HDR-RP-MISSING",
                title="Missing Referrer-Policy Header",
                category=Category.SECURITY_HEADERS,
                severity=Severity.LOW,
                cvss_score=3.1,
                description="The server does not specify a Referrer-Policy.",
                impact="Sensitive URLs with session tokens, user IDs, or internal query parameters may leak in the Referer header to external third parties.",
                remediation="Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                evidence="Header 'Referrer-Policy' is absent.",
                compliance_tags=["OWASP A05:2021"],
            )
        )
        metadata["defensive_headers_missing"].append("Referrer-Policy")
    elif rp.lower().strip() in ["unsafe-url", "no-referrer-when-downgrade"]:
        findings.append(
            Finding(
                id="HDR-RP-INSECURE",
                title=f"Insecure Referrer-Policy Configured: '{rp}'",
                category=Category.SECURITY_HEADERS,
                severity=Severity.LOW,
                cvss_score=3.5,
                description=f"The policy '{rp}' exposes full URLs including paths and query parameters to cross-origin destinations.",
                impact="Potential leakage of confidential query strings and endpoints.",
                remediation="Change policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
                evidence=f"Referrer-Policy: {rp}",
                compliance_tags=["OWASP A05:2021"],
            )
        )
    else:
        metadata["defensive_headers_present"].append("Referrer-Policy")

    # 6. Permissions-Policy
    pp = headers.get("permissions-policy") or headers.get("feature-policy")
    if not pp:
        findings.append(
            Finding(
                id="HDR-PP-MISSING",
                title="Missing Permissions-Policy Header",
                category=Category.SECURITY_HEADERS,
                severity=Severity.LOW,
                cvss_score=2.5,
                description="The server does not restrict browser device capabilities using Permissions-Policy.",
                impact="Enables embedded third-party scripts or iframes to request sensitive browser APIs (camera, geolocation, microphone).",
                remediation="Configure 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
                evidence="Header 'Permissions-Policy' is absent.",
                compliance_tags=["Modern Defensive Standards"],
            )
        )
        metadata["defensive_headers_missing"].append("Permissions-Policy")
    else:
        metadata["defensive_headers_present"].append("Permissions-Policy")

    # 7. Information Disclosure: Server, X-Powered-By, etc.
    leak_headers = [
        ("server", "Web Server Version Banner Disclosure"),
        ("x-powered-by", "Application Framework Disclosure (X-Powered-By)"),
        ("x-aspnet-version", "ASP.NET Version Disclosure"),
        ("x-aspnetmvc-version", "ASP.NET MVC Version Disclosure"),
        ("x-generator", "CMS / Generator Disclosure"),
    ]

    for h_name, h_title in leak_headers:
        val = headers.get(h_name)
        if val:
            # Check if version numbers are disclosed
            has_version = any(char.isdigit() for char in val)
            findings.append(
                Finding(
                    id=f"LEAK-{h_name.upper()}",
                    title=h_title,
                    category=Category.TECH_STACK_CVE,
                    severity=Severity.LOW if has_version else Severity.INFO,
                    cvss_score=3.3 if has_version else 0.0,
                    description=f"The server exposes internal technology metadata via '{h_name}: {val}'.",
                    impact="Facilitates targeted attacker reconnaissance and CVE matching.",
                    remediation=f"Mask or suppress the '{h_name}' response header in your web server/application configuration.",
                    evidence=f"{h_name}: {val}",
                    compliance_tags=["OWASP A05:2021"],
                )
            )

    return findings, metadata
