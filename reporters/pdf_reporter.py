"""PDF Reporter for WebSecAudit using fpdf2.
Generates an enterprise-grade security audit and BIA assessment report with high-legibility typography,
clean white table backgrounds, structured specification grids, and zero asterisks (*).
"""

import os
from typing import Dict, Any, List
from fpdf import FPDF
from fpdf.enums import XPos, YPos

from core.models import AuditResult, Finding

# Corporate Color Palette (RGB)
PRIMARY_NAVY = (24, 43, 73)
SECONDARY_SLATE = (71, 85, 105)
LIGHT_BG = (245, 247, 250)
BORDER_GRAY = (226, 232, 240)
HEADER_TINT = (241, 245, 249)
TEXT_DARK = (30, 41, 59)
TEXT_MUTED = (100, 116, 139)

SEVERITY_COLORS = {
    "CRITICAL": (185, 28, 28),    # Deep Red
    "HIGH": (220, 38, 38),        # Bright Red
    "MEDIUM": (217, 119, 6),      # Amber/Orange
    "LOW": (37, 99, 235),         # Blue
    "INFO": (100, 116, 139),      # Slate Gray
}

GRADE_COLORS = {
    "A+": (22, 163, 74),
    "A": (34, 197, 94),
    "B": (14, 165, 233),
    "C": (234, 179, 8),
    "D": (249, 115, 22),
    "F": (220, 38, 38),
}


def sanitize(text: Any) -> str:
    """Sanitize strings for compatibility with standard FPDF Helvetica font (latin-1)."""
    if text is None:
        return ""
    s = str(text)
    replacements = {
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2013": "-",
        "\u2014": "--",
        "\u2022": "-",
        "\u2026": "...",
        "\u00a0": " ",
        "\u2192": "->",
        "\u2713": "[x]",
        "\u2717": "[ ]",
    }
    for orig, rep in replacements.items():
        s = s.replace(orig, rep)
    return s.encode("latin-1", errors="replace").decode("latin-1")


class SecurityAuditPDF(FPDF):
    """Custom FPDF document class with corporate header and footer."""

    def __init__(self, target_url: str):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.target_url = target_url
        self.set_margins(15, 15, 15)
        self.set_auto_page_break(auto=True, margin=15)
        self.alias_nb_pages()

    def header(self):
        if self.page_no() > 1:
            self.set_font("helvetica", "B", 8.5)
            self.set_text_color(*SECONDARY_SLATE)
            self.cell(
                0, 7, sanitize(f"WebSecAudit Assessment Report  |  Target: {self.target_url}"),
                border="B", align="L",
                new_x=XPos.LMARGIN, new_y=YPos.NEXT
            )
            self.ln(4)

    def footer(self):
        self.set_y(-12)
        self.set_font("helvetica", "I", 8.5)
        self.set_text_color(*TEXT_MUTED)
        page_str = f"Page {self.page_no()} of {{nb}}"
        self.cell(
            0, 8, sanitize(f"CONFIDENTIAL & PROPRIETARY  |  Capstone BIA Deliverable  |  {page_str}"),
            border="T", align="C",
            new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )


def generate_pdf_report(result: AuditResult, output_path: str):
    """Generate a multi-page executive security posture and BIA PDF report."""
    pdf = SecurityAuditPDF(result.target_url)
    pdf.add_page()
    epw = pdf.epw  # 180mm on A4 with 15mm margins

    # --- COVER BANNER ---
    banner_h = 38
    pdf.set_fill_color(*PRIMARY_NAVY)
    pdf.rect(15, 15, epw, banner_h, "F")

    pdf.set_xy(20, 18)
    pdf.set_font("helvetica", "B", 16)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 8, "WEB APPLICATION SECURITY AUDIT & BIA REPORT", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_xy(20, 27)
    pdf.set_font("helvetica", "B", 9.5)
    pdf.set_text_color(147, 197, 253)  # Soft Sky Blue
    pdf.cell(0, 5.5, sanitize(f"Target: {result.target_url}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_xy(20, 33.5)
    pdf.set_font("helvetica", "", 8.5)
    pdf.set_text_color(203, 213, 225)
    pdf.cell(0, 5.5, sanitize(f"Automated Defensive Posture Assessment  |  Date: {result.scan_timestamp}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # --- TARGET METADATA & POSTURE SCORE CARDS ---
    col_w = (epw - 6) / 2
    card_h = 52
    start_y = 57

    # Left Box: Target Profile (Clean alignment without asterisks)
    pdf.set_fill_color(*LIGHT_BG)
    pdf.set_draw_color(*BORDER_GRAY)
    pdf.rect(15, start_y, col_w, card_h, "DF")

    pdf.set_xy(19, start_y + 3)
    pdf.set_font("helvetica", "B", 11)
    pdf.set_text_color(*PRIMARY_NAVY)
    pdf.cell(col_w - 8, 6, "Target Infrastructure Profile", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_x(19)
    pdf.set_font("helvetica", "B", 8.5)
    pdf.set_text_color(*SECONDARY_SLATE)
    pdf.cell(col_w - 8, 4.5, "Target URL:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_x(19)
    pdf.set_font("helvetica", "", 8.0)
    pdf.set_text_color(*TEXT_DARK)
    pdf.multi_cell(col_w - 8, 4.0, sanitize(result.target_url), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_x(19)
    pdf.set_font("helvetica", "B", 8.5)
    pdf.set_text_color(*SECONDARY_SLATE)
    pdf.cell(24, 5, "IP Address:", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_font("helvetica", "", 8.5)
    pdf.set_text_color(*TEXT_DARK)
    pdf.cell(col_w - 32, 5, sanitize(f"{result.ip_address or 'Unknown'}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    server_str = result.metadata.get("fingerprint", {}).get("server_banner", "Suppressed")
    pdf.set_x(19)
    pdf.set_font("helvetica", "B", 8.5)
    pdf.set_text_color(*SECONDARY_SLATE)
    pdf.cell(24, 5, "Web Server:", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_font("helvetica", "", 8.5)
    pdf.set_text_color(*TEXT_DARK)
    pdf.cell(col_w - 32, 5, sanitize(f"{server_str}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_x(19)
    pdf.set_font("helvetica", "B", 8.5)
    pdf.set_text_color(*SECONDARY_SLATE)
    pdf.cell(24, 5, "Duration:", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_font("helvetica", "", 8.5)
    pdf.set_text_color(*TEXT_DARK)
    pdf.cell(col_w - 32, 5, sanitize(f"{result.scan_duration_seconds} seconds"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Right Box: Security Posture Rating
    grade_color = GRADE_COLORS.get(result.grade, PRIMARY_NAVY)
    pdf.set_fill_color(*LIGHT_BG)
    right_x = 15 + col_w + 6
    pdf.rect(right_x, start_y, col_w, card_h, "DF")

    pdf.set_xy(right_x + 4, start_y + 3)
    pdf.set_font("helvetica", "B", 11)
    pdf.set_text_color(*PRIMARY_NAVY)
    pdf.cell(col_w - 8, 6, "Defensive Posture Score", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_xy(right_x + 4, start_y + 11)
    pdf.set_font("helvetica", "B", 26)
    pdf.set_text_color(*grade_color)
    pdf.cell(32, 13, f"{result.score}", align="L", new_x=XPos.RIGHT, new_y=YPos.TOP)

    pdf.set_font("helvetica", "B", 26)
    pdf.cell(24, 13, f"[{result.grade}]", align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_xy(right_x + 4, start_y + 27)
    pdf.set_font("helvetica", "I", 8.5)
    pdf.set_text_color(*TEXT_MUTED)
    pdf.multi_cell(col_w - 8, 4.5, sanitize(result.grade_description), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_y(113)

    # --- SECTION 1: EXECUTIVE SUMMARY & FINDINGS DISTRIBUTION ---
    pdf.set_font("helvetica", "B", 13)
    pdf.set_text_color(*PRIMARY_NAVY)
    pdf.cell(0, 8, "1. Executive Summary & Findings Distribution", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(*PRIMARY_NAVY)
    pdf.set_line_width(0.5)
    pdf.line(15, pdf.get_y(), 15 + epw, pdf.get_y())
    pdf.ln(4)

    counts = result.count_by_severity()
    sev_order = [
        ("CRITICAL", "CVSS 9.0-10.0"),
        ("HIGH", "CVSS 7.0-8.9"),
        ("MEDIUM", "CVSS 4.0-6.9"),
        ("LOW", "CVSS 0.1-3.9"),
        ("INFO", "CVSS 0.0"),
    ]
    start_x = 16
    badge_y = pdf.get_y()
    badge_h = 20

    for i, (sev, cvss_range) in enumerate(sev_order):
        c_rgb = SEVERITY_COLORS.get(sev, TEXT_MUTED)
        box_x = start_x + (i * 35.5)
        pdf.set_fill_color(*c_rgb)
        pdf.rect(box_x, badge_y, 33, badge_h, "F")

        # Tier title
        pdf.set_xy(box_x, badge_y + 1.8)
        pdf.set_font("helvetica", "B", 8.5)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(33, 4, sev, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Count
        pdf.set_xy(box_x, badge_y + 6.0)
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(33, 6.5, str(counts.get(sev, 0)), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # CVSS Range
        pdf.set_xy(box_x, badge_y + 13.5)
        pdf.set_font("helvetica", "", 7.5)
        pdf.set_text_color(240, 245, 255)
        pdf.cell(33, 4, cvss_range, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_y(badge_y + badge_h + 5)

    # Executive narrative
    if result.bia:
        pdf.set_x(15)
        pdf.set_font("helvetica", "", 9.5)
        pdf.set_text_color(*TEXT_DARK)
        pdf.multi_cell(epw, 5.2, sanitize(result.bia.executive_summary), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

    # --- SECTION 2: BUSINESS IMPACT ANALYSIS (BIA) & REGULATORY COMPLIANCE ---
    pdf.set_x(15)
    pdf.set_font("helvetica", "B", 13)
    pdf.set_text_color(*PRIMARY_NAVY)
    pdf.cell(0, 8, "2. Business Impact Analysis (BIA) & Regulatory Compliance", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.line(15, pdf.get_y(), 15 + epw, pdf.get_y())
    pdf.ln(4)

    if result.bia:
        cia_rows = [
            ("Confidentiality (CIA)", result.bia.confidentiality_risk, "Risk of unauthorized data interception, session cookie hijacking, or internal server metadata leakage."),
            ("Integrity (CIA)", result.bia.integrity_risk, "Exposure to clickjacking, malicious script execution (XSS), or unauthorized cross-origin tampering (CORS)."),
            ("Availability (CIA)", result.bia.availability_risk, "Susceptibility to denial-of-service, resource exhaustion, or operational downtime from unpatched software."),
            ("Financial Exposure", result.bia.financial_impact_rating.split(" - ")[0], sanitize(result.bia.financial_impact_rating)),
            ("Brand & Reputation", result.bia.reputational_risk_rating.split(" - ")[0], sanitize(result.bia.reputational_risk_rating)),
        ]

        # Reset fill and border colors to ensure clean crisp white background
        pdf.set_fill_color(255, 255, 255)
        pdf.set_draw_color(203, 213, 225)
        pdf.set_font("helvetica", size=8.5)

        with pdf.table(col_widths=(45, 33, epw - 78), first_row_as_headings=False) as table:
            # Header Row
            pdf.set_font("helvetica", "B", 9)
            pdf.set_text_color(*PRIMARY_NAVY)
            h_row = table.row()
            h_row.cell("Impact Vector")
            h_row.cell("Evaluated Risk")
            h_row.cell("Business Consequence & Scope")

            # Content Rows (Clean White Background)
            pdf.set_font("helvetica", "", 8.5)
            pdf.set_text_color(*TEXT_DARK)
            for vector, rating, desc in cia_rows:
                row = table.row()
                row.cell(sanitize(vector))
                row.cell(sanitize(rating))
                row.cell(sanitize(desc))

        pdf.ln(4)

        # Regulatory Compliance Table (Clean White Background)
        if result.bia.regulatory_exposure:
            pdf.set_fill_color(255, 255, 255)
            pdf.set_draw_color(203, 213, 225)
            pdf.set_font("helvetica", size=8.5)
            with pdf.table(col_widths=(48, epw - 48), first_row_as_headings=False) as table:
                pdf.set_font("helvetica", "B", 9)
                pdf.set_text_color(*PRIMARY_NAVY)
                h_row = table.row()
                h_row.cell("Regulatory Framework")
                h_row.cell("Compliance Status & Applicable Standard")

                pdf.set_font("helvetica", "", 8.5)
                pdf.set_text_color(*TEXT_DARK)
                for std, status in result.bia.regulatory_exposure.items():
                    row = table.row()
                    row.cell(sanitize(std))
                    row.cell(sanitize(status))

    # --- SECTION 3: TECHNICAL AUDIT BREAKDOWN (Structured Grids, Zero Asterisks) ---
    pdf.add_page()
    pdf.set_font("helvetica", "B", 13)
    pdf.set_text_color(*PRIMARY_NAVY)
    pdf.cell(0, 8, "3. Transport Layer & Defensive Controls Audit Details", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.line(15, pdf.get_y(), 15 + epw, pdf.get_y())
    pdf.ln(4)

    # Subsection A: Transport Layer & Cryptographic Architecture Table
    ssl_meta = result.metadata.get("ssl", {})
    pdf.set_font("helvetica", "B", 10.5)
    pdf.set_text_color(*SECONDARY_SLATE)
    pdf.cell(0, 7, "A. Transport Layer Security (TLS/SSL Architecture & Certificate Audit):", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    tls_ver = ssl_meta.get("tls_version", "N/A")
    cipher = ssl_meta.get("cipher_suite", "N/A")
    valid_from = ssl_meta.get("cert_valid_from", "N/A")
    expiry = ssl_meta.get("cert_expiry", "N/A")
    days = ssl_meta.get("days_until_expiry")
    is_valid_days = isinstance(days, (int, float))
    days_str = f"{days} days remaining" if is_valid_days else "N/A"
    if is_valid_days:
        status_tag = "EXPIRED" if days < 0 else ("EXPIRING SOON" if days < 30 else "VALID & ACTIVE")
    else:
        status_tag = "N/A / UNKNOWN"

    issuer = ssl_meta.get("cert_issuer", "N/A")
    subject = ssl_meta.get("cert_subject", "N/A")
    key_type = ssl_meta.get("key_type", "N/A")
    key_size = ssl_meta.get("key_size", "")
    sig_algo = ssl_meta.get("signature_algo", "N/A")

    sans = ssl_meta.get("san_list", [])
    san_display = ", ".join(sans[:6]) + (f" (+{len(sans)-6} more)" if len(sans) > 6 else "") if sans else "None"

    tls_grid = [
        ("Negotiated Protocol", f"{tls_ver} (Preferred Cipher: {cipher})"),
        ("Certificate Status", f"{status_tag} ({days_str})"),
        ("Validity Window", f"{valid_from} to {expiry}"),
        ("Cryptographic Keys", f"{key_type} {key_size} bits (Signature Digest: {str(sig_algo).upper()})"),
        ("Subject Identity", f"{subject}"),
        ("Certificate Issuer", f"{issuer}"),
        ("Alternative Domains", f"{san_display}"),
    ]

    # Reset fill color to clean white for specifications table
    pdf.set_fill_color(255, 255, 255)
    pdf.set_draw_color(203, 213, 225)
    pdf.set_font("helvetica", size=8.5)

    with pdf.table(col_widths=(52, epw - 52), first_row_as_headings=False) as table:
        for param_label, param_val in tls_grid:
            row = table.row()
            pdf.set_font("helvetica", "B", 8.5)
            pdf.set_text_color(*PRIMARY_NAVY)
            row.cell(sanitize(param_label))

            pdf.set_font("helvetica", "", 8.5)
            pdf.set_text_color(*TEXT_DARK)
            row.cell(sanitize(param_val))

    pdf.ln(4)

    # Subsection B: HTTP Defensive Headers Table
    hdr_meta = result.metadata.get("headers", {})
    pdf.set_font("helvetica", "B", 10.5)
    pdf.set_text_color(*SECONDARY_SLATE)
    pdf.cell(0, 7, "B. HTTP Defensive Headers Audit Summary:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    present_hdrs = ", ".join(hdr_meta.get("defensive_headers_present", [])) or "None identified"
    missing_hdrs = ", ".join(hdr_meta.get("defensive_headers_missing", [])) or "None (All baseline headers satisfied)"

    hdr_grid = [
        ("Active Defensive Headers", present_hdrs),
        ("Missing Defensive Headers", missing_hdrs),
    ]

    pdf.set_fill_color(255, 255, 255)
    pdf.set_draw_color(203, 213, 225)
    pdf.set_font("helvetica", size=8.5)

    with pdf.table(col_widths=(52, epw - 52), first_row_as_headings=False) as table:
        for label, val in hdr_grid:
            row = table.row()
            pdf.set_font("helvetica", "B", 8.5)
            pdf.set_text_color(*PRIMARY_NAVY)
            row.cell(sanitize(label))

            pdf.set_font("helvetica", "", 8.5)
            pdf.set_text_color(*TEXT_DARK)
            row.cell(sanitize(val))

    pdf.ln(4)

    # Subsection C: Cookie Hygiene Table
    cookie_meta = result.metadata.get("cookies", {})
    pdf.set_font("helvetica", "B", 10.5)
    pdf.set_text_color(*SECONDARY_SLATE)
    pdf.cell(0, 7, "C. Cookie Security & Session Hygiene:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    audited_cookies = cookie_meta.get("audited_cookies", [])
    cookie_rows = []
    if audited_cookies:
        for c in audited_cookies[:4]:
            cookie_rows.append((c['name'], f"Secure={c['secure']} | HttpOnly={c['httponly']} | SameSite={c['samesite']}"))
    else:
        cookie_rows.append(("Cookie Directives", "No Set-Cookie directives were issued on the audited page."))

    pdf.set_fill_color(255, 255, 255)
    pdf.set_draw_color(203, 213, 225)
    pdf.set_font("helvetica", size=8.5)

    with pdf.table(col_widths=(52, epw - 52), first_row_as_headings=False) as table:
        for label, val in cookie_rows:
            row = table.row()
            pdf.set_font("helvetica", "B", 8.5)
            pdf.set_text_color(*PRIMARY_NAVY)
            row.cell(sanitize(label))

            pdf.set_font("helvetica", "", 8.5)
            pdf.set_text_color(*TEXT_DARK)
            row.cell(sanitize(val))

    pdf.ln(4)

    # --- SECTION 4: DETAILED FINDINGS & REMEDIATION ---
    pdf.set_font("helvetica", "B", 13)
    pdf.set_text_color(*PRIMARY_NAVY)
    pdf.cell(0, 8, "4. Detailed Security Findings & Remediation Guide", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.line(15, pdf.get_y(), 15 + epw, pdf.get_y())
    pdf.ln(4)

    if not result.findings:
        pdf.set_font("helvetica", "I", 10)
        pdf.set_text_color(*TEXT_MUTED)
        pdf.cell(0, 9, "No vulnerabilities or defensive misconfigurations were identified.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        for f in result.findings:
            if pdf.get_y() > 215:
                pdf.add_page()

            sev_name = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            sev_rgb = SEVERITY_COLORS.get(sev_name, TEXT_MUTED)

            # Finding Title Bar
            pdf.set_fill_color(*sev_rgb)
            pdf.rect(15, pdf.get_y(), epw, 7.5, "F")

            pdf.set_xy(17, pdf.get_y() + 1.2)
            pdf.set_font("helvetica", "B", 9.5)
            pdf.set_text_color(255, 255, 255)
            header_title = f"[{sev_name}] {f.id}: {f.title}  |  CVSS: {f.cvss_score:.1f}"
            pdf.cell(epw - 4, 5, sanitize(header_title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.set_x(15)
            pdf.ln(2)

            label_w = 26
            val_w = epw - label_w

            # Category
            pdf.set_font("helvetica", "B", 9)
            pdf.set_text_color(*SECONDARY_SLATE)
            pdf.cell(label_w, 5, "Category:", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("helvetica", "", 9)
            pdf.set_text_color(*TEXT_DARK)
            compliance_str = " | ".join(f.compliance_tags) if f.compliance_tags else "General Hygiene"
            cat_val = f.category.value if hasattr(f.category, "value") else str(f.category)
            pdf.cell(val_w, 5, sanitize(f"{cat_val}  ({compliance_str})"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            # Description
            pdf.set_font("helvetica", "B", 9)
            pdf.set_text_color(*SECONDARY_SLATE)
            pdf.cell(label_w, 5, "Description:", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("helvetica", "", 9)
            pdf.set_text_color(*TEXT_DARK)
            pdf.multi_cell(val_w, 4.6, sanitize(f.description), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            # Impact
            pdf.set_font("helvetica", "B", 9)
            pdf.set_text_color(*SECONDARY_SLATE)
            pdf.cell(label_w, 5, "Impact:", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("helvetica", "", 9)
            pdf.set_text_color(*TEXT_DARK)
            pdf.multi_cell(val_w, 4.6, sanitize(f.impact), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            # Evidence
            if f.evidence:
                pdf.set_font("helvetica", "B", 9)
                pdf.set_text_color(*SECONDARY_SLATE)
                pdf.cell(label_w, 4.5, "Evidence:", new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.set_font("helvetica", "I", 8.5)
                pdf.set_text_color(70, 70, 70)
                pdf.multi_cell(val_w, 4.2, sanitize(f.evidence[:160]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            # Remediation
            pdf.set_font("helvetica", "B", 9)
            pdf.set_text_color(22, 101, 52)  # Dark Green
            pdf.cell(label_w, 5, "Remediation:", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("helvetica", "", 9)
            pdf.set_text_color(*TEXT_DARK)
            pdf.multi_cell(val_w, 4.6, sanitize(f.remediation), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.ln(3.5)

    # --- SECTION 5: STRATEGIC REMEDIATION ROADMAP ---
    if pdf.get_y() > 200:
        pdf.add_page()
    else:
        pdf.ln(4)

    pdf.set_x(15)
    pdf.set_font("helvetica", "B", 13)
    pdf.set_text_color(*PRIMARY_NAVY)
    pdf.cell(0, 8, "5. Strategic Remediation Roadmap & Operational Next Steps", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.line(15, pdf.get_y(), 15 + epw, pdf.get_y())
    pdf.ln(4)

    roadmap_steps = [
        ("Phase 1 (Immediate: 24-48 hrs)", "Resolve all CRITICAL and HIGH severity findings. Deploy missing HSTS headers, renew expiring SSL certificates, and restrict any exposed repository or config files."),
        ("Phase 2 (Short-Term: 1-2 weeks)", "Implement a hardened Content-Security-Policy (CSP) to mitigate Cross-Site Scripting (XSS). Ensure all session cookies mandate HttpOnly and SameSite=Lax/Strict."),
        ("Phase 3 (Operational Hygiene)", "Suppress server technology banners (Server, X-Powered-By). Deploy RFC 9116 security.txt to facilitate ethical vulnerability disclosures, and integrate automated scans into CI/CD pipelines."),
    ]

    pdf.set_fill_color(255, 255, 255)
    pdf.set_draw_color(203, 213, 225)
    pdf.set_font("helvetica", size=8.5)

    with pdf.table(col_widths=(55, epw - 55), first_row_as_headings=False) as table:
        pdf.set_font("helvetica", "B", 9)
        pdf.set_text_color(*PRIMARY_NAVY)
        h_row = table.row()
        h_row.cell("Remediation Milestone")
        h_row.cell("Action Plan & Operational Scope")

        pdf.set_font("helvetica", "", 8.5)
        pdf.set_text_color(*TEXT_DARK)
        for phase_title, phase_desc in roadmap_steps:
            row = table.row()
            pdf.set_font("helvetica", "B", 8.5)
            pdf.set_text_color(*PRIMARY_NAVY)
            row.cell(sanitize(phase_title))

            pdf.set_font("helvetica", "", 8.5)
            pdf.set_text_color(*TEXT_DARK)
            row.cell(sanitize(phase_desc))

    # Save to file
    out_dir = os.path.dirname(output_path)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    pdf.output(output_path)
