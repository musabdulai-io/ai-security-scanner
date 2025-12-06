# backend/app/features/scanner/reporting/pdf.py
"""PDF report generator using WeasyPrint."""

import os
import sys
from pathlib import Path
from typing import Dict, List

from jinja2 import Environment, FileSystemLoader

from backend.app.core import logs
from backend.app.core.config import settings
from ..models import ScanResult, AttackResult


def _configure_weasyprint_macos():
    """Configure library paths for WeasyPrint on macOS.

    WeasyPrint requires native libraries (glib, pango, etc.) that are installed
    via Homebrew. This function adds Homebrew lib paths to DYLD_LIBRARY_PATH
    so the dynamic linker can find them.

    Works with: poetry, pipx, docker, venv, deployed environments.
    """
    if sys.platform != "darwin":
        return

    # Homebrew paths: /opt/homebrew/lib (Apple Silicon) or /usr/local/lib (Intel)
    homebrew_paths = ["/opt/homebrew/lib", "/usr/local/lib"]
    current_path = os.environ.get("DYLD_LIBRARY_PATH", "")

    paths_to_add = [p for p in homebrew_paths if os.path.isdir(p) and p not in current_path]
    if paths_to_add:
        new_path = ":".join(paths_to_add + ([current_path] if current_path else []))
        os.environ["DYLD_LIBRARY_PATH"] = new_path

# Sorting orders
STATUS_ORDER = {"FAIL": 0, "ERROR": 1, "PASS": 2}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def calculate_score(severity_counts: Dict[str, int]) -> int:
    """Calculate security score (0-100) based on vulnerability severities."""
    deductions = (
        severity_counts.get("CRITICAL", 0) * 25 +
        severity_counts.get("HIGH", 0) * 15 +
        severity_counts.get("MEDIUM", 0) * 5 +
        severity_counts.get("LOW", 0) * 2
    )
    return max(0, 100 - deductions)


def generate_pdf_report(
    result: ScanResult,
    output_path: str = "report.pdf",
    verbose: bool = False,
) -> str:
    """
    Generate PDF report from scan result using WeasyPrint.

    Args:
        result: ScanResult object containing scan findings
        output_path: Path to save the PDF report
        verbose: Include raw request/response logs in report

    Returns:
        Absolute path to the generated report file
    """
    # Configure library paths before importing weasyprint
    _configure_weasyprint_macos()

    try:
        from weasyprint import HTML, CSS
    except (ImportError, OSError) as e:
        error_msg = str(e)
        if "cannot load library" in error_msg or "OSError" in str(type(e)):
            logs.error(
                "WeasyPrint system dependencies missing. On macOS: brew install pango gdk-pixbuf libffi",
                "reporting",
            )
            raise ImportError(
                "WeasyPrint requires system libraries. Install with:\n"
                "  macOS: brew install pango gdk-pixbuf libffi\n"
                "  Ubuntu: apt install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0\n"
                "Then restart your terminal and try again."
            )
        else:
            logs.error(
                "WeasyPrint not installed. Install with: pip install weasyprint",
                "reporting",
            )
            raise ImportError(
                "WeasyPrint is required for PDF generation. "
                "Install with: pip install weasyprint"
            )

    logs.info(f"Generating PDF report", "reporting", {"output": output_path})

    # Get template directory (backend/templates/)
    template_dir = Path(__file__).parent.parent.parent.parent.parent / "templates"

    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report.html")

    # Calculate severity counts
    severity_counts: Dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }
    for vuln in result.vulnerabilities:
        severity_counts[vuln.severity.value] += 1

    # Calculate security score
    score = calculate_score(severity_counts)

    # Group attack results by category
    security_attacks: List[AttackResult] = []
    reliability_attacks: List[AttackResult] = []
    cost_attacks: List[AttackResult] = []

    for attack in result.attack_results:
        category = getattr(attack, "category", None)
        if category:
            cat_value = category.value if hasattr(category, "value") else str(category)
        else:
            cat_value = "security"

        if cat_value == "security":
            security_attacks.append(attack)
        elif cat_value == "reliability":
            reliability_attacks.append(attack)
        elif cat_value == "cost":
            cost_attacks.append(attack)
        else:
            security_attacks.append(attack)

    # Sort attacks: FAIL first, then ERROR, then PASS
    security_attacks.sort(key=lambda x: STATUS_ORDER.get(x.status, 3))
    reliability_attacks.sort(key=lambda x: STATUS_ORDER.get(x.status, 3))
    cost_attacks.sort(key=lambda x: STATUS_ORDER.get(x.status, 3))

    # Count passed attacks
    passed_count = sum(1 for attack in result.attack_results if attack.status == "PASS")

    # Group vulnerabilities by attack category
    security_vulns = []
    reliability_vulns = []
    cost_vulns = []

    # Create a mapping of attack type to category
    attack_category_map = {}
    for attack in result.attack_results:
        category = getattr(attack, "category", None)
        if category:
            cat_value = category.value if hasattr(category, "value") else str(category)
        else:
            cat_value = "security"
        attack_category_map[attack.attack_type] = cat_value

    # Categorize vulnerabilities
    for vuln in result.vulnerabilities:
        vuln_category = "security"
        for attack_type, category in attack_category_map.items():
            if attack_type.lower() in vuln.name.lower():
                vuln_category = category
                break

        if vuln_category == "reliability":
            reliability_vulns.append(vuln)
        elif vuln_category == "cost":
            cost_vulns.append(vuln)
        else:
            security_vulns.append(vuln)

    # Sort vulnerabilities by severity: CRITICAL first
    security_vulns.sort(key=lambda x: SEVERITY_ORDER.get(x.severity.value, 4))
    reliability_vulns.sort(key=lambda x: SEVERITY_ORDER.get(x.severity.value, 4))
    cost_vulns.sort(key=lambda x: SEVERITY_ORDER.get(x.severity.value, 4))

    # Render template
    html_content = template.render(
        # Metadata
        target_url=result.target_url,
        scan_id=result.scan_id,
        timestamp=result.timestamp,
        duration=result.duration_seconds,

        # Scorecard
        score=score,
        critical_count=severity_counts["CRITICAL"],
        high_count=severity_counts["HIGH"],
        medium_count=severity_counts["MEDIUM"],
        low_count=severity_counts["LOW"],
        passed_count=passed_count,

        # Backward compatibility
        result=result,
        has_vulnerabilities=len(result.vulnerabilities) > 0,
        severity_counts=severity_counts,
        total_vulnerabilities=len(result.vulnerabilities),

        # CTA
        cta_url=settings.CTA_URL,
        cta_text=settings.CTA_TEXT,

        # Categorized & sorted data
        security_attacks=security_attacks,
        reliability_attacks=reliability_attacks,
        cost_attacks=cost_attacks,
        security_vulns=security_vulns,
        reliability_vulns=reliability_vulns,
        cost_vulns=cost_vulns,
        security_vuln_count=len(security_vulns),
        reliability_vuln_count=len(reliability_vulns),
        cost_vuln_count=len(cost_vulns),

        # Verbose mode - disabled for PDF (raw logs are excluded via no-print class)
        include_raw_log=False,
        raw_log=[],
    )

    # Convert HTML to PDF
    output_file = Path(output_path).absolute()
    HTML(string=html_content).write_pdf(str(output_file))

    logs.info(f"PDF report generated", "reporting", {"path": str(output_file)})
    return str(output_file)
