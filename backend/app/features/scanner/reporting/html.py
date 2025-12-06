# backend/app/features/scanner/reporting/html.py
"""HTML report generator using Jinja2 templates."""

import webbrowser
from pathlib import Path
from typing import Dict, List

from jinja2 import Environment, FileSystemLoader

from backend.app.core import logs
from backend.app.core.config import settings
from ..models import ScanResult, Severity, AttackResult


def generate_html_report(result: ScanResult, output_path: str = "report.html") -> str:
    """
    Generate HTML report from scan result.

    Args:
        result: ScanResult object containing scan findings
        output_path: Path to save the HTML report

    Returns:
        Absolute path to the generated report file
    """
    logs.info(f"Generating HTML report", "reporting", {"output": output_path})

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

    # Categorize vulnerabilities based on which attack found them
    for vuln in result.vulnerabilities:
        # Try to determine category from vulnerability name
        vuln_category = "security"  # default
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

    # Render template
    html = template.render(
        result=result,
        has_vulnerabilities=len(result.vulnerabilities) > 0,
        severity_counts=severity_counts,
        total_vulnerabilities=len(result.vulnerabilities),
        cta_url=settings.CTA_URL,
        cta_text=settings.CTA_TEXT,
        # Categorized data
        security_attacks=security_attacks,
        reliability_attacks=reliability_attacks,
        cost_attacks=cost_attacks,
        security_vulns=security_vulns,
        reliability_vulns=reliability_vulns,
        cost_vulns=cost_vulns,
        security_vuln_count=len(security_vulns),
        reliability_vuln_count=len(reliability_vulns),
        cost_vuln_count=len(cost_vulns),
    )

    # Write to file
    output_file = Path(output_path).absolute()
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    logs.info(f"Report generated", "reporting", {"path": str(output_file)})
    return str(output_file)


def open_report(path: str) -> None:
    """
    Open the HTML report in the default web browser.

    Args:
        path: Path to the HTML report file
    """
    file_url = f"file://{Path(path).absolute()}"
    logs.debug(f"Opening report in browser", "reporting", {"url": file_url})
    webbrowser.open(file_url)
