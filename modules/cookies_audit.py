"""Cookie Security and Session Hygiene Audit Module.
Evaluates Set-Cookie attributes (Secure, HttpOnly, SameSite, and Cookie Prefixes).
"""

from typing import List, Dict, Any, Tuple
import requests

from core.models import Finding, Severity, Category


def audit_cookies(response: requests.Response, is_https: bool = True) -> Tuple[List[Finding], Dict[str, Any]]:
    """Audit all cookies set by the server for defense-in-depth flags."""
    findings: List[Finding] = []
    metadata: Dict[str, Any] = {
        "cookies_detected_count": 0,
        "audited_cookies": [],
    }

    # Extract all Set-Cookie raw header strings
    raw_cookie_headers = []
    if "set-cookie" in response.headers:
        # In requests, multiple Set-Cookie headers might be collapsed or in response.raw.headers
        if hasattr(response.raw, "headers") and hasattr(response.raw.headers, "getlist"):
            raw_cookie_headers = response.raw.headers.getlist("Set-Cookie")
        if not raw_cookie_headers:
            raw_cookie_headers = [response.headers.get("set-cookie")]

    metadata["cookies_detected_count"] = len(raw_cookie_headers)

    if not raw_cookie_headers:
        return findings, metadata

    no_secure_cookies: List[str] = []
    no_httponly_cookies: List[str] = []
    no_samesite_cookies: List[str] = []
    has_session_cookie_insecure = False

    for cookie_header in raw_cookie_headers:
        parts = [p.strip() for p in cookie_header.split(";")]
        if not parts:
            continue

        cookie_pair = parts[0].split("=", 1)
        cookie_name = cookie_pair[0].strip()

        attributes = {}
        for attr in parts[1:]:
            attr_pair = attr.split("=", 1)
            attr_key = attr_pair[0].lower()
            attr_val = attr_pair[1] if len(attr_pair) > 1 else True
            attributes[attr_key] = attr_val

        has_secure = "secure" in attributes
        has_httponly = "httponly" in attributes
        samesite = attributes.get("samesite")

        metadata["audited_cookies"].append({
            "name": cookie_name,
            "secure": has_secure,
            "httponly": has_httponly,
            "samesite": samesite if samesite else "None Specified",
        })

        is_likely_session = any(
            term in cookie_name.lower()
            for term in ["sess", "auth", "token", "jwt", "id", "login", "admin", "csrftoken", "xsrf"]
        )
        if is_likely_session and (not has_secure or not has_httponly):
            has_session_cookie_insecure = True

        if is_https and not has_secure:
            no_secure_cookies.append(cookie_name)

        if not has_httponly:
            no_httponly_cookies.append(cookie_name)

        if not samesite:
            no_samesite_cookies.append(cookie_name)

        # Cookie Prefix Verification
        if cookie_name.startswith("__Host-"):
            if not has_secure or attributes.get("domain") or attributes.get("path") != "/":
                findings.append(
                    Finding(
                        id=f"COOKIE-INVALID-HOST-PREFIX-{cookie_name.upper()}",
                        title=f"Invalid '__Host-' Prefix Implementation on '{cookie_name}'",
                        category=Category.COOKIE_HYGIENE,
                        severity=Severity.MEDIUM,
                        cvss_score=5.0,
                        description="Cookies with the '__Host-' prefix must be Secure, have Path=/, and must not specify a Domain attribute.",
                        impact="Browser will reject or fail to lock cookie to the exact host.",
                        remediation="Ensure __Host- cookies have Secure, Path=/, and no Domain directive.",
                        evidence=f"Set-Cookie: {cookie_header}",
                        compliance_tags=["RFC 6265bis"],
                    )
                )

    # 1. Aggregate Secure Flag Finding
    if no_secure_cookies:
        cookie_list_str = ", ".join(f"'{c}'" for c in no_secure_cookies[:5])
        if len(no_secure_cookies) > 5:
            cookie_list_str += f" (+{len(no_secure_cookies)-5} more)"
        severity = Severity.HIGH if has_session_cookie_insecure else Severity.MEDIUM
        findings.append(
            Finding(
                id="COOKIE-SECURE-FLAG-MISSING",
                title=f"Cookies Missing 'Secure' Attribute ({len(no_secure_cookies)} cookie{'s' if len(no_secure_cookies)>1 else ''})",
                category=Category.COOKIE_HYGIENE,
                severity=severity,
                cvss_score=7.1 if severity == Severity.HIGH else 5.3,
                description=f"The following cookies were issued over HTTPS without the 'Secure' flag: {cookie_list_str}.",
                impact="Unencrypted transit risk: cookies can be leaked if a user triggers plain HTTP requests to the target.",
                remediation="Append '; Secure' to all Set-Cookie header directives in application configuration.",
                evidence=f"Affected Cookies: {cookie_list_str}",
                compliance_tags=["PCI-DSS 4.0: Req 8.2", "OWASP A05:2021", "HIPAA § 164.312(e)(1)"],
            )
        )

    # 2. Aggregate HttpOnly Flag Finding
    if no_httponly_cookies:
        cookie_list_str = ", ".join(f"'{c}'" for c in no_httponly_cookies[:5])
        if len(no_httponly_cookies) > 5:
            cookie_list_str += f" (+{len(no_httponly_cookies)-5} more)"
        severity = Severity.HIGH if has_session_cookie_insecure else Severity.MEDIUM
        findings.append(
            Finding(
                id="COOKIE-HTTPONLY-FLAG-MISSING",
                title=f"Cookies Missing 'HttpOnly' Attribute ({len(no_httponly_cookies)} cookie{'s' if len(no_httponly_cookies)>1 else ''})",
                category=Category.COOKIE_HYGIENE,
                severity=severity,
                cvss_score=6.5 if severity == Severity.HIGH else 4.3,
                description=f"The following cookies lack the 'HttpOnly' attribute: {cookie_list_str}.",
                impact="Client-side script access risk: cookies can be read by malicious JavaScript if XSS exists.",
                remediation="Append '; HttpOnly' to all Set-Cookie directives for sensitive and session cookies.",
                evidence=f"Affected Cookies: {cookie_list_str}",
                compliance_tags=["OWASP A03:2021", "PCI-DSS 4.0: Req 8.2"],
            )
        )

    # 3. Aggregate SameSite Attribute Finding
    if no_samesite_cookies:
        cookie_list_str = ", ".join(f"'{c}'" for c in no_samesite_cookies[:5])
        if len(no_samesite_cookies) > 5:
            cookie_list_str += f" (+{len(no_samesite_cookies)-5} more)"
        findings.append(
            Finding(
                id="COOKIE-SAMESITE-MISSING",
                title=f"Cookies Missing 'SameSite' Attribute ({len(no_samesite_cookies)} cookie{'s' if len(no_samesite_cookies)>1 else ''})",
                category=Category.COOKIE_HYGIENE,
                severity=Severity.MEDIUM,
                cvss_score=4.3,
                description=f"The following cookies omit the SameSite attribute (Lax/Strict): {cookie_list_str}.",
                impact="Elevated CSRF exposure across third-party cross-site request contexts.",
                remediation="Declare '; SameSite=Lax' or '; SameSite=Strict' on all Set-Cookie headers.",
                evidence=f"Affected Cookies: {cookie_list_str}",
                compliance_tags=["OWASP A01:2021", "RFC 6265bis"],
            )
        )

    return findings, metadata
