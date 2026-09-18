#!/usr/bin/env python3
"""
WebSecAudit - Open-Source Web Application Security Posture & BIA Engine.
A modular defensive auditing scanner inspired by Qualys SSL Labs and Qualys WAS.
"""

import sys
import re
import argparse
from urllib.parse import urlparse
from colorama import init, Fore, Style

from core.engine import AuditEngine
from reporters.console_reporter import print_console_report
from reporters.json_reporter import export_json_report
from reporters.pdf_reporter import generate_pdf_report

init(autoreset=True)


def derive_clean_target_name(target: str) -> str:
    """Extract clean domain/hostname for report filenames (e.g. 'amazon.in')."""
    raw = target.strip()
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    host = parsed.hostname or "target"
    if host.startswith("www."):
        host = host[4:]
    clean = re.sub(r"[^\w\.-]", "_", host)
    return clean


def display_banner():
    banner = f"""{Fore.CYAN}{Style.BRIGHT}
 __          __  _     _____               _             _ _ _   
 \\ \\        / / | |   / ____|             /\\            | (_) |  
  \\ \\  /\\  / /__| |__| (___   ___  ___   /  \\  _   _  __| |_| |_ 
   \\ \\/  \\/ / _ \\ '_ \\\\___ \\ / _ \\/ __| / /\\ \\| | | |/ _` | | __|
    \\  /\\  /  __/ |_) |___) |  __/ (__ / ____ \\ |_| | (_| | | |_ 
     \\/  \\/ \\___|_.__/_____/ \\___|\\___/_/    \\_\\__,_|\\__,_|_|\\__|
       Automated Defensive Posture Scanner & BIA Assessment Engine
    {Style.RESET_ALL}"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description="WebSecAudit - Automated Web Security Posture & Business Impact Analysis Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python main.py https://amazon.in
  python main.py https://amazon.in --pdf
  python main.py https://amazon.in --pdf --json
  python main.py https://amazon.in --timeout 15 --no-cve
        """,
    )

    parser.add_argument("target", nargs="?", help="Target domain or URL (e.g. https://amazon.in)")
    parser.add_argument(
        "--pdf",
        nargs="?",
        const=True,
        default=None,
        metavar="PATH",
        help="Generate an executive PDF report (defaults to '<target>_report.pdf')",
    )
    parser.add_argument(
        "--json",
        nargs="?",
        const=True,
        default=None,
        metavar="PATH",
        help="Export structured findings to JSON file (defaults to '<target>_report.json')",
    )
    parser.add_argument("--timeout", type=int, default=10, help="Network request timeout in seconds (default: 10)")
    parser.add_argument("--no-cve", action="store_true", help="Disable online OSV.dev CVE API lookup (offline mode)")
    parser.add_argument("--quiet", action="store_true", help="Suppress real-time step progress output")

    args = parser.parse_args()

    if not args.target:
        display_banner()
        parser.print_help()
        sys.exit(1)

    if not args.quiet:
        display_banner()

    clean_name = derive_clean_target_name(args.target)

    # Determine dynamic PDF output filename
    pdf_path = None
    if args.pdf is True:
        pdf_path = f"{clean_name}_report.pdf"
    elif isinstance(args.pdf, str):
        if args.pdf.strip().lower() in ["report.pdf", "audit_report.pdf", ""]:
            pdf_path = f"{clean_name}_report.pdf"
        else:
            pdf_path = args.pdf

    # Determine dynamic JSON output filename
    json_path = None
    if args.json is True:
        json_path = f"{clean_name}_report.json"
    elif isinstance(args.json, str):
        if args.json.strip().lower() in ["report.json", "audit_report.json", ""]:
            json_path = f"{clean_name}_report.json"
        else:
            json_path = args.json

    def progress(step_name: str, message: str):
        if not args.quiet:
            print(f"{Fore.BLUE}[*] {Fore.WHITE}{step_name:<25}: {Fore.LIGHTBLACK_EX if hasattr(Fore, 'LIGHTBLACK_EX') else Fore.WHITE}{message}")

    try:
        engine = AuditEngine(
            timeout=args.timeout,
            check_online_cve=not args.no_cve,
            progress_callback=progress,
        )

        audit_result = engine.run_audit(args.target)

        # 1. Console Terminal Output
        print_console_report(audit_result)

        # 2. JSON Export
        if json_path:
            export_json_report(audit_result, file_path=json_path)
            print(f"{Fore.GREEN}[+] Machine-readable JSON report exported: {Fore.WHITE}{json_path}")

        # 3. PDF Export
        if pdf_path:
            print(f"{Fore.BLUE}[*] Compiling executive PDF deliverable with fpdf2...")
            generate_pdf_report(audit_result, output_path=pdf_path)
            print(f"{Fore.GREEN}[+] Enterprise BIA PDF report generated: {Fore.WHITE}{pdf_path}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Audit cancelled by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal audit execution error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
