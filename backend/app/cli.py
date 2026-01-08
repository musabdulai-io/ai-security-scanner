# backend/app/cli.py
"""Typer CLI application for AI Security Scanner."""

import asyncio
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from backend.app.core import logs, settings
from backend.app.core.curl_parser import parse_curl, CurlParseError
from backend.app.features.scanner.reporting import (
    generate_html_report,
    open_report,
    show_attack_table,
    show_error,
    show_failures_summary,
    show_progress,
    show_summary,
)
from backend.app.features.scanner.services import ScannerService

app = typer.Typer(
    name="scanner",
    help="AI Security Scanner - Audit LLM/RAG applications for vulnerabilities",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


@app.command()
def scan(
    target: Optional[str] = typer.Argument(
        None,
        help="Target LLM/RAG endpoint URL (e.g., https://example.com)",
    ),
    output: str = typer.Option(
        "report.html",
        "--output",
        "-o",
        help="Output file path for the HTML report",
    ),
    fast: bool = typer.Option(
        False,
        "--fast",
        "-f",
        help="Skip slow tests (RAG poisoning upload)",
    ),
    header: Optional[List[str]] = typer.Option(
        None,
        "--header",
        "-H",
        help="Custom headers (e.g., 'Authorization: Bearer KEY')",
    ),
    curl: Optional[str] = typer.Option(
        None,
        "--curl",
        help="Import target configuration from a cURL command",
    ),
    competitor: Optional[List[str]] = typer.Option(
        None,
        "--competitor",
        help="Competitor names to test against (e.g., 'Acme Corp')",
    ),
    concurrency: int = typer.Option(
        5,
        "--concurrency",
        "-c",
        help="Number of concurrent requests",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Include raw AI responses in the report for analysis",
    ),
    no_open: bool = typer.Option(
        False,
        "--no-open",
        help="Don't automatically open the report in browser",
    ),
    test_data_dir: Optional[str] = typer.Option(
        None,
        "--test-data-dir",
        "-d",
        help="Directory containing custom test documents for RAG attacks",
    ),
) -> None:
    """
    Scan an LLM/RAG application for security vulnerabilities.

    Example usage:

        scanner scan https://example.com

        scanner scan https://example.com --fast --output audit.html

        scanner scan https://example.com -H "Authorization: Bearer sk-xxx"

        scanner scan --curl "curl https://api.example.com -H 'Auth: token'"

        scanner scan https://example.com --competitor "Acme" --competitor "ACME Corp"
    """
    try:
        # Handle cURL import
        if curl:
            try:
                curl_config = parse_curl(curl)
                target = curl_config.base_url
                # Merge cURL headers with explicit headers (explicit takes precedence)
                for key, value in curl_config.headers.items():
                    if key not in (header or []):
                        if header is None:
                            header = []
                        header.append(f"{key}: {value}")
                console.print(f"[dim]Imported from cURL: {curl_config.url}[/dim]")
            except CurlParseError as e:
                show_error(f"Failed to parse cURL command: {e}")
                raise typer.Exit(1)

        # Validate target
        if not target:
            show_error("Target URL is required. Provide it as argument or via --curl")
            raise typer.Exit(1)

        # Validate and set test data directory
        if test_data_dir:
            test_path = Path(test_data_dir)
            if not test_path.exists():
                show_error(f"Test data directory does not exist: {test_data_dir}")
                raise typer.Exit(1)
            if not test_path.is_dir():
                show_error(f"Test data path is not a directory: {test_data_dir}")
                raise typer.Exit(1)
            # Update settings with the provided path
            settings.TEST_DATA_DIR = str(test_path.resolve())

        # Parse headers
        headers = {}
        if header:
            for h in header:
                if ":" in h:
                    key, value = h.split(":", 1)
                    headers[key.strip()] = value.strip()

        # Parse competitors
        competitors = list(competitor) if competitor else None

        # Show banner
        console.print()
        console.print(
            f"[bold cyan]AI Security Scanner[/bold cyan] v{settings.APP_VERSION}"
        )
        console.print()
        console.print(f"Target: [cyan]{target}[/cyan]")
        console.print(f"Output: [dim]{output}[/dim]")
        if fast:
            console.print("[yellow]Fast mode: Skipping RAG upload tests[/yellow]")
        if test_data_dir:
            console.print(f"[cyan]Test data: {settings.TEST_DATA_DIR}[/cyan]")
        if competitors:
            console.print(f"[dim]Competitors: {', '.join(competitors)}[/dim]")
        console.print()

        # Run the scan
        result = asyncio.run(_run_scan(target, fast, headers, competitors))

        # Display results - failures first, then category tables
        show_failures_summary(result)
        show_attack_table(result.attack_results)
        show_summary(result)

        # Generate report
        report_path = generate_html_report(result, output, verbose=verbose)
        console.print()
        console.print(f"[dim]Report saved to: {report_path}[/dim]")

        # Open report in browser
        if not no_open:
            open_report(report_path)

        # Exit with error code if vulnerabilities found
        if result.vulnerabilities:
            raise typer.Exit(1)

    except typer.Exit:
        raise
    except Exception as e:
        show_error(str(e))
        raise typer.Exit(1)


async def _run_scan(
    target: str,
    fast: bool,
    headers: dict,
    competitors: Optional[List[str]] = None,
):
    """Run the scan asynchronously with progress display."""
    scanner = ScannerService(competitors=competitors)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Initializing scan...", total=None)

        def on_progress(message: str) -> None:
            # Update spinner description
            progress.update(task, description=message)
            # Also print the message
            show_progress(message)

        result = await scanner.scan(
            target_url=target,
            fast=fast,
            headers=headers,
            on_progress=on_progress,
        )

    return result


@app.command()
def packs(
    tier: Optional[str] = typer.Option(
        None,
        "--tier",
        "-t",
        help="Filter by tier: community, pro",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed pack information",
    ),
) -> None:
    """List all available attack packs."""
    from rich.table import Table
    from backend.app.features.scanner.packs import get_registry, PackTier

    registry = get_registry()

    # Filter by tier if specified
    packs_list = list(registry.packs.values())
    if tier:
        try:
            tier_enum = PackTier(tier.lower())
            packs_list = [p for p in packs_list if p.metadata.tier == tier_enum]
        except ValueError:
            show_error(f"Invalid tier: {tier}. Use: community, pro")
            raise typer.Exit(1)

    if not packs_list:
        console.print("[yellow]No packs found.[/yellow]")
        if tier:
            console.print("[dim]Tip: Install pro packs with: pip install ai-security-scanner-pro[/dim]")
        raise typer.Exit(0)

    table = Table(title="Available Attack Packs")
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="dim")
    table.add_column("Tier", style="green")
    table.add_column("Description")
    if verbose:
        table.add_column("Attacks", style="yellow")

    for pack in packs_list:
        meta = pack.metadata
        row = [
            meta.name,
            meta.version,
            meta.tier.value,
            meta.description[:50] + "..." if len(meta.description) > 50 else meta.description,
        ]
        if verbose:
            attacks = pack.get_attack_modules()
            row.append(str(len(attacks)))
        table.add_row(*row)

    console.print()
    console.print(table)
    console.print()

    # Show any load errors
    if registry.load_errors:
        console.print("[yellow]Pack loading errors:[/yellow]")
        for name, error in registry.load_errors.items():
            console.print(f"  [red]{name}[/red]: {error}")


@app.command()
def attacks(
    pack: Optional[str] = typer.Option(
        None,
        "--pack",
        "-p",
        help="Filter attacks by pack name",
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category: security, reliability, cost",
    ),
) -> None:
    """List all available attack modules."""
    from rich.table import Table
    from backend.app.features.scanner.packs import get_registry

    registry = get_registry()

    table = Table(title="Available Attack Modules")
    table.add_column("Attack Name", style="cyan")
    table.add_column("Category", style="green")
    table.add_column("Pack", style="yellow")
    table.add_column("Description")

    for pack_name, pack_obj in registry.packs.items():
        if pack and pack_name != pack:
            continue

        modules = pack_obj.get_attack_modules()
        for module in modules:
            module_category = getattr(module, "category", "security")
            if category and module_category != category:
                continue

            desc = module.description if hasattr(module, "description") else ""
            table.add_row(
                module.name,
                module_category,
                pack_name,
                desc[:40] + "..." if len(desc) > 40 else desc,
            )

    console.print()
    console.print(table)
    console.print()


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"AI Security Scanner v{settings.APP_VERSION}")


@app.command()
def info() -> None:
    """Show configuration information."""
    console.print()
    console.print("[bold]Configuration[/bold]")
    console.print()
    console.print(f"  App Name:      {settings.APP_NAME}")
    console.print(f"  Version:       {settings.APP_VERSION}")
    console.print(f"  Environment:   {settings.ENVIRONMENT}")
    console.print(f"  Sandbox URL:   {settings.SANDBOX_URL}")
    console.print(f"  Timeout:       {settings.REQUEST_TIMEOUT}s")
    console.print()


if __name__ == "__main__":
    app()
