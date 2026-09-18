"""Console Reporter for WebSecAudit.
Displays clean, robust, colorized audit summaries and findings tables in the terminal.
"""

import sys
from colorama import init, Fore, Style
from tabulate import tabulate

from core.models import AuditResult

# Ensure stdout handles encoding safely on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

init(autoreset=True)

SEVERITY_COLORS = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH": Fore.LIGHTRED_EX,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.CYAN,
    "INFO": Fore.WHITE,
}

GRADE_COLORS = {
    "A+": Fore.GREEN + Style.BRIGHT,
    "A": Fore.GREEN,
    "B": Fore.CYAN + Style.BRIGHT,
    "C": Fore.YELLOW + Style.BRIGHT,
    "D": Fore.MAGENTA + Style.BRIGHT,
    "F": Fore.RED + Style.BRIGHT,
}


def print_console_report(result: AuditResult):
    """Print an executive-grade terminal summary of the audit results."""
    divider = "=" * 78
    subdivider = "-" * 78

    print("\n" + Fore.CYAN + Style.BRIGHT + divider)
    print(Fore.CYAN + Style.BRIGHT + "       WebSecAudit - Web Security Posture & BIA Assessment Engine")
    print(Fore.CYAN + Style.BRIGHT + divider)

    # Target Metadata
    print(f"\n{Fore.WHITE + Style.BRIGHT}Target Assessment Overview:")
    print(f"  • Target URL     : {Fore.YELLOW}{result.target_url}")
    print(f"  • IP Address     : {Fore.WHITE}{result.ip_address or 'Unknown'}")
    print(f"  • Timestamp      : {Fore.WHITE}{result.scan_timestamp}")
    print(f"  • Scan Duration  : {Fore.WHITE}{result.scan_duration_seconds} seconds")

    # Score & Grade Banner
    grade_color = GRADE_COLORS.get(result.grade, Fore.WHITE)
    print(f"\n{Fore.WHITE + Style.BRIGHT}Security Posture Rating:")
    print(f"  • Overall Score  : {grade_color}{result.score} / 100.0")
    print(f"  • Letter Grade   : {grade_color}{result.grade} {Style.RESET_ALL}({result.grade_description})")

    # Severity Breakdown
    counts = result.count_by_severity()
    crit = f"{Fore.RED + Style.BRIGHT}{counts['CRITICAL']}{Style.RESET_ALL}"
    high = f"{Fore.LIGHTRED_EX}{counts['HIGH']}{Style.RESET_ALL}"
    med = f"{Fore.YELLOW}{counts['MEDIUM']}{Style.RESET_ALL}"
    low = f"{Fore.CYAN}{counts['LOW']}{Style.RESET_ALL}"
    info = f"{Fore.WHITE}{counts['INFO']}{Style.RESET_ALL}"

    print(f"\n{Fore.WHITE + Style.BRIGHT}Vulnerabilities & Posture Flaws Discovered (CVSS 3.1):")
    print(
        f"  [{crit} Critical (9.0-10.0)]  "
        f"[{high} High (7.0-8.9)]  "
        f"[{med} Medium (4.0-6.9)]  "
        f"[{low} Low (0.1-3.9)]  "
        f"[{info} Info (0.0)]"
    )

    # Findings Table (Using ASCII grid for universal terminal compatibility)
    if result.findings:
        print(f"\n{Fore.WHITE + Style.BRIGHT}Detailed Findings Breakdown:")
        table_rows = []
        for f in result.findings:
            sev_name = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            color = SEVERITY_COLORS.get(sev_name, Fore.WHITE)
            sev_str = f"{color}{sev_name}{Style.RESET_ALL}"
            table_rows.append([
                f.id,
                sev_str,
                f"{f.cvss_score:.1f}",
                f.title[:42] + ("..." if len(f.title) > 42 else ""),
                f.remediation[:38] + ("..." if len(f.remediation) > 38 else ""),
            ])

        headers = ["ID", "Severity", "CVSS", "Finding Title", "Remediation Snippet"]
        print(tabulate(table_rows, headers=headers, tablefmt="grid"))
    else:
        print(f"\n{Fore.GREEN}No vulnerabilities or configuration misconfigurations detected!")

    # BIA Section
    if result.bia:
        print(f"\n{Fore.WHITE + Style.BRIGHT}Business Impact Analysis (BIA) & Regulatory Posture:")
        print(subdivider)
        print(f"  • Confidentiality Risk : {result.bia.confidentiality_risk}")
        print(f"  • Integrity Risk       : {result.bia.integrity_risk}")
        print(f"  • Availability Risk    : {result.bia.availability_risk}")
        print(f"  • Financial Impact     : {result.bia.financial_impact_rating}")
        print(f"  • Reputational Risk    : {result.bia.reputational_risk_rating}")

        if result.bia.regulatory_exposure:
            print(f"\n  Compliance Matrix:")
            for std, status in result.bia.regulatory_exposure.items():
                stat_color = Fore.GREEN if "COMPLIANT" in status and "NON" not in status else (Fore.RED if "NON-COMPLIANT" in status else Fore.YELLOW)
                print(f"    - {std:22}: {stat_color}{status}{Style.RESET_ALL}")

        print(f"\n{Fore.WHITE + Style.BRIGHT}Executive Narrative:")
        print(f"  {Fore.WHITE}{result.bia.executive_summary}\n")

    print(Fore.CYAN + Style.BRIGHT + divider + "\n")
