"""Configuration and constants for WebSecAudit."""

DEFAULT_TIMEOUT = 10
SOCKET_TIMEOUT = 5
MAX_REDIRECTS = 5

USER_AGENT = "WebSecAudit/1.0 (Defensive Web Security Posture Scanner; Capstone BIA Engine)"

DEFAULT_REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "close",
}

# Curated high-risk paths for bounded attack surface discovery
SENSITIVE_PATHS = [
    {"path": "/.env", "name": "Environment Config File", "severity": "CRITICAL"},
    {"path": "/.git/HEAD", "name": "Git Repository Metadata", "severity": "CRITICAL"},
    {"path": "/.git/config", "name": "Git Configuration Disclosure", "severity": "CRITICAL"},
    {"path": "/robots.txt", "name": "Robots Exclusion File", "severity": "INFO"},
    {"path": "/.well-known/security.txt", "name": "Security Contact Policy", "severity": "INFO"},
    {"path": "/security.txt", "name": "Security Contact Policy (Root)", "severity": "INFO"},
    {"path": "/server-status", "name": "Apache Server Status Page", "severity": "HIGH"},
    {"path": "/phpinfo.php", "name": "PHP Information Leak", "severity": "HIGH"},
    {"path": "/backup.zip", "name": "Database/Site Backup Archive", "severity": "CRITICAL"},
    {"path": "/.DS_Store", "name": "macOS Directory Metadata File", "severity": "MEDIUM"},
    {"path": "/web.config", "name": "IIS Web Configuration File", "severity": "CRITICAL"},
    {"path": "/crossdomain.xml", "name": "Flash Cross-Domain Policy", "severity": "LOW"},
]

# Scoring deductions per finding severity
SEVERITY_DEDUCTIONS = {
    "CRITICAL": 25.0,
    "HIGH": 15.0,
    "MEDIUM": 7.0,
    "LOW": 2.0,
    "INFO": 0.0,
}

# Grade thresholds
GRADE_SCALE = [
    (95.0, "A+", "Exceptional defensive hygiene with robust modern controls."),
    (90.0, "A", "Strong defensive posture with minor non-critical improvements recommended."),
    (80.0, "B", "Good posture, but missing defense-in-depth headers or secondary safeguards."),
    (70.0, "C", "Adequate baseline, but notable configuration weaknesses increase exposure."),
    (60.0, "D", "Poor posture with significant missing defensive controls and risk of exploitation."),
    (0.0, "F", "Failing security posture with critical vulnerabilities or missing essential encryption."),
]

# OSV.dev REST API endpoint for vulnerability queries
OSV_QUERY_ENDPOINT = "https://api.osv.dev/v1/query"
