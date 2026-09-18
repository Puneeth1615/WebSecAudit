# WebSecAudit: Automated Web Security Posture & BIA Engine

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Standard](https://img.shields.io/badge/framework-CVSS%203.1%20%7C%20BIA%20%7C%20PCI--DSS%204.0-red.svg)](https://www.first.org/cvss/)
[![Reporting](https://img.shields.io/badge/deliverables-Terminal%20%7C%20JSON%20%7C%20PDF-purple.svg)](https://py-pdf.github.io/fpdf2/)

An enterprise-grade, open-source web application security posture scanner and Business Impact Analysis (BIA) engine written in Python.

WebSecAudit benchmarks its core audit checks against enterprise industry standards—specifically **Qualys SSL Labs** and **Qualys WAS (Web Application Scanning)**—delivering transport-layer verification, defensive header hygiene, session cookie audits, technology fingerprinting, known CVE correlation, and multi-page executive PDF reports at **$0 licensing cost**.

---

## Architecture & Modular Design

```
                               ┌─────────────────────────────────────────┐
                               │       WebSecAudit Orchestrator          │
                               │               (main.py)                 │
                               └────────────────────┬────────────────────┘
                                                    │
                 ┌──────────────────────────────────┴──────────────────────────────────┐
                 ▼                                                                     ▼
    ┌──────────────────────────┐                                          ┌──────────────────────────┐
    │     Target Validation    │                                          │      Network Client      │
    │  - URL Normalization     │                                          │  - Requests Session      │
    │  - DNS & IP Resolution   │                                          │  - Raw TLS/SSL Sockets   │
    └────────────┬─────────────┘                                          └────────────┬─────────────┘
                 │                                                                     │
                 └──────────────────────────────────┬──────────────────────────────────┘
                                                    │
                                  ┌─────────────────┴─────────────────┐
                                  ▼                                   ▼
                       ┌──────────────────────┐           ┌──────────────────────┐
                       │   5-Pillar Auditing  │           │ Scoring & BIA Engine │
                       │       Engine         │           │   (core/scoring.py)  │
                       └──────────┬───────────┘           └───────────┬──────────┘
                                  │                                   │
      ┌───────────────────────────┼───────────────────────────┐       │
      ▼                           ▼                           ▼       ▼
┌──────────────┐            ┌──────────────┐            ┌──────────────┐
│   Pillar 1   │            │   Pillar 2   │            │   Pillar 3   │
│  Transport   │            │   Defensive  │            │ Cookie Flags │
│   SSL/TLS    │            │ HTTP Headers │            │ & Session    │
└──────────────┘            └──────────────┘            └──────────────┘
      ▼                           ▼                           ▼
┌──────────────┐            ┌──────────────┐            ┌──────────────┐
│   Pillar 4   │            │   Pillar 5   │            │ CVSS Rating  │
│  Tech Stack  │            │ Attack Surf. │            │  & Letter    │
│ & CVE Map    │            │  & Exposure  │            │    Grade     │
└──────────────┘            └──────────────┘            └──────────────┘
                                  │
                                  ▼
                 ┌──────────────────────────────────┐
                 │       Enterprise Reporters       │
                 ├──────────────────────────────────┤
                 │ • Colorized Console Dashboard    │
                 │ • Machine-Readable JSON (CI/CD)  │
                 │ • Multi-Page Executive PDF (BIA) │
                 └──────────────────────────────────┘
```

---

## The 5 Core Audit Pillars

### 1. SSL/TLS Transport Deep Audit (Qualys SSL Labs Benchmark)
- Direct socket TLS Server Name Indication (SNI) handshake.
- Inspection of negotiated TLS protocols (`TLSv1.2`, `TLSv1.3`, and deprecation flags for `TLSv1.0`/`TLSv1.1`/`SSLv3`).
- Certificate validity, expiration countdown, and signature algorithm audit (flags `SHA-1`/`MD5`).
- Public key size analysis (verifies RSA >= 2048 bits and modern ECDSA).
- Subject Alternative Names (SAN) domain wildcard and hostname mismatch validation.

### 2. Modern HTTP Defensive Headers Audit
- **HSTS (`Strict-Transport-Security`)**: Enforces HTTPS, checks `max-age` duration, `includeSubDomains`, and `preload`.
- **CSP (`Content-Security-Policy`)**: Flags missing CSP, `unsafe-inline`, `unsafe-eval`, and wildcard `*` resource directives.
- **Clickjacking Protection**: Audits `X-Frame-Options` (`DENY`/`SAMEORIGIN`) and CSP `frame-ancestors`.
- **MIME Sniffing**: Validates `X-Content-Type-Options: nosniff`.
- **Referrer Privacy**: Detects URL query parameter leakage in `Referrer-Policy`.
- **Device API Sandboxing**: Checks `Permissions-Policy` (camera, microphone, geolocation restrictions).

### 3. Cookie Security & Session Hygiene
- Audits `Set-Cookie` directives for session tokens and tracking cookies.
- **`Secure` Flag**: Mandates encrypted transmission over HTTPS.
- **`HttpOnly` Flag**: Protects cookies from JavaScript access (`document.cookie`) to prevent XSS session hijacking.
- **`SameSite` Attribute**: Mitigates Cross-Site Request Forgery (`Strict`, `Lax`, or flags insecure `None`).
- **Cookie Prefixes**: Verifies RFC 6265bis compliance for `__Host-` and `__Secure-` identifiers.

### 4. Technology Fingerprinting & Known Vulnerability (CVE) Mapping
- Server banner inspection (`Server`, `X-Powered-By`, `X-AspNet-Version`).
- DOM framework and CMS fingerprinting (WordPress, Django, Laravel, React, Vue, Angular, jQuery).
- Real-time querying of the **OSV.dev REST API** (Google/OpenSSF open-source vulnerability database) for detected component versions.
- Offline curated signature database mapping known high-impact CVEs (e.g. Apache path traversal, Nginx resolver vulnerabilities, out-of-date PHP runtimes).

### 5. Attack Surface & Information Exposure Discovery
- Concurrent multi-threaded non-destructive probing of sensitive endpoints (`.env`, `.git/HEAD`, `.git/config`, `server-status`, `phpinfo.php`, `backup.zip`, `.DS_Store`, `web.config`).
- RFC 9116 `security.txt` vulnerability disclosure policy verification.
- `robots.txt` parsing for disclosed administrative or private directories.
- **CORS Misconfiguration Testing**: Probes for arbitrary Origin reflection with `Access-Control-Allow-Credentials: true`.

---

## Business Impact Analysis (BIA) & Scoring

WebSecAudit computes an objective security score starting at **100.0** with CVSS 3.1-aligned weighted deductions:
- **CRITICAL** (-25.0 pts): Direct remote execution, exposed secrets (`.env`), arbitrary CORS reflection with credentials.
- **HIGH** (-15.0 pts): Missing HSTS, expired/self-signed SSL certificates, missing `Secure`/`HttpOnly` flags on session cookies.
- **MEDIUM** (-7.0 pts): Missing CSP, clickjacking vulnerability (no X-Frame-Options), wildcard CSP directives.
- **LOW** (-2.0 pts): Missing MIME-sniffing protection, server banner disclosure, missing Referrer-Policy.
- **INFO** (0.0 pts): Missing `security.txt`, TLS 1.3 upgrade recommendations.

### Posture Grade Scale
| Score | Grade | Enterprise Posture Interpretation |
| :--- | :---: | :--- |
| **95 - 100** | **A+** | Exceptional defensive hygiene with modern proactive controls. |
| **90 - 94** | **A** | Strong defensive posture; minor non-critical improvements recommended. |
| **80 - 89** | **B** | Good baseline posture; missing defense-in-depth headers. |
| **70 - 79** | **C** | Adequate baseline; notable configuration weaknesses increase exposure. |
| **60 - 69** | **D** | Poor posture; significant missing controls and elevated attack risk. |
| **< 60** | **F** | Failing posture; critical vulnerabilities or missing encryption. |

### Regulatory Compliance Mapping
Findings automatically map into compliance status for:
- **PCI-DSS 4.0**: Requirement 4.1 (Strong Cryptography) & Requirement 6.4 (Web Security Controls)
- **HIPAA Security Rule**: § 164.312(e)(1) Transmission Security & ePHI Safeguards
- **GDPR Article 32**: Technical and Organizational Security Measures

---

## Installation

```bash
# Clone repository
git clone https://github.com/your-username/WebSecAudit.git
cd WebSecAudit

# Install dependencies
pip install -r requirements.txt
```

---

## Usage Guide

### Basic Scan
```bash
python main.py https://example.com
```

### Full Assessment with PDF & JSON Deliverables
```bash
python main.py https://example.com --pdf audit_report.pdf --json audit_report.json
```

### Fast Offline Mode (Skip Online CVE Queries)
```bash
python main.py https://example.com --no-cve --timeout 5
```

### CLI Command Options
```
positional arguments:
  target             Target domain or URL (e.g. https://example.com)

options:
  -h, --help         Show this help message and exit
  --pdf PATH         Generate an enterprise-grade multi-page PDF report
  --json PATH        Export structured findings to JSON for CI/CD pipelines
  --timeout TIMEOUT  Network request timeout in seconds (default: 10)
  --no-cve           Disable online OSV.dev CVE API lookup (offline mode)
  --quiet            Suppress real-time step progress output
```

---

## Automated Test Suite

WebSecAudit includes an automated unit testing suite validating scoring mathematics, BIA compliance triggers, HTTP header evaluation rules, cookie flag parsers, and PDF/JSON generation:

```bash
python -m unittest discover tests
```

---

## Capstone & Resume Highlighting

### Suggested Resume Bullet Points:
> **WebSecAudit – Open-Source Web Vulnerability & Security Posture Scanner (Python)**
> - Engineered a modular Python security auditing engine benchmarked against Qualys SSL Labs and Qualys WAS, auditing TLS cipher suites, certificate chains, and HTTP defensive headers (HSTS, CSP, X-Frame-Options).
> - Implemented concurrent attack surface discovery and automated CVE correlation via Google's OSV.dev REST API and signature heuristics.
> - Built an automated Business Impact Analysis (BIA) and CVSS 3.1 scoring model generating executive PDF reports and machine-readable JSON for CI/CD DevSecOps pipelines.

### Key Interview Talking Points:
1. **Socket-level TLS Handshake**: Explain how direct socket connections wrap TLS with Server Name Indication (SNI) and parse X.509 DER certificates using `cryptography` to evaluate key lengths, hashing algorithms, and SAN domain wildcards.
2. **Business Impact Analysis (BIA)**: Explain why translating a technical finding (e.g., missing HSTS) into business consequences (e.g., PCI-DSS 4.0 Requirement 4.1 failure and SSL-stripping risk) is what differentiates an AppSec professional from a script-runner.
3. **Safe & Non-Destructive Scanning**: Explain how bounded concurrent probing (`ThreadPoolExecutor`) prevents DoS conditions, and how verification logic (checking content patterns rather than just HTTP 200) eliminates false-positives on custom 404 error pages.
