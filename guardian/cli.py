"""CLI interface for Guardian."""

import asyncio
import json
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from guardian.config import get_settings
from guardian.core import Guardian
from guardian.dashboard import run_dashboard
from guardian.reporting import Reporter

app = typer.Typer(
    help="Guardian - Unified monitoring for npm packages, GitHub repos, and deployments"
)
console = Console()


def _configure_logging(json_output: bool = False) -> None:
    """Configure logging based on output mode.

    In JSON mode, suppress INFO logs from httpx/httpcore to keep output clean.
    """
    if json_output:
        # Suppress verbose HTTP logs in JSON mode
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("guardian").setLevel(logging.WARNING)


@app.command()
def check(
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
    watch: bool = typer.Option(False, "--watch", "-w", help="Watch mode (continuous checks)"),
    interval: int = typer.Option(
        None, "--interval", "-i", help="Interval in seconds for watch mode"
    ),
    skip_validation: bool = typer.Option(
        False, "--skip-validation", help="Skip configuration validation"
    ),
    env_file: str | None = typer.Option(
        None,
        "--env-file",
        help="Optional env file path to load (overrides default env_file search).",
    ),
) -> None:
    """Run monitoring checks."""
    _configure_logging(json_output)
    settings = get_settings(env_file=env_file)
    guardian = Guardian(settings)
    reporter = Reporter(settings)

    # Validate configuration
    if not skip_validation:
        warnings = guardian.validate_configuration()
        if warnings:
            console.print("[bold yellow]Configuration Warnings:[/bold yellow]")
            for warning in warnings:
                console.print(f"  ⚠ {warning}")
            console.print()

    async def run_check():
        report = await guardian.run_checks()

        if json_output:
            report_dict = reporter._report_to_dict(report)
            console.print(json.dumps(report_dict, indent=2))
        else:
            await reporter.report(report)

    if watch:
        # Don't run watch mode if no checkers configured
        if not skip_validation and not guardian.checkers:
            console.print(
                "[bold red]Error: No checkers configured. Cannot run in watch mode.[/bold red]"
            )
            console.print("Configure at least one checker or use --skip-validation to proceed.")
            raise typer.Exit(code=1)

        interval_seconds = interval or settings.check_interval_seconds
        console.print(f"[bold]Watching with interval: {interval_seconds}s[/bold]\n")

        async def watch_loop():
            while True:
                await run_check()
                await asyncio.sleep(interval_seconds)

        asyncio.run(watch_loop())
    else:
        asyncio.run(run_check())


@app.command()
def config() -> None:
    """Show current configuration."""
    settings = get_settings()

    console.print("[bold blue]Guardian Configuration[/bold blue]\n")

    console.print(f"GitHub: {'✓' if settings.github_token else '✗'}")
    if settings.github_org:
        console.print(f"  Organization: {settings.github_org}")
    if settings.github_repos_to_monitor:
        console.print(f"  Repos: {', '.join(settings.github_repos_to_monitor)}")

    console.print(f"\nVercel: {'✓' if settings.vercel_token else '✗'}")
    if settings.vercel_team_id:
        console.print(f"  Team ID: {settings.vercel_team_id}")
    if settings.vercel_projects_to_monitor:
        console.print(f"  Projects: {', '.join(settings.vercel_projects_to_monitor)}")

    console.print(f"\nFly.io: {'✓' if settings.fly_api_token else '✗'}")
    if settings.fly_apps_to_monitor:
        console.print(f"  Apps: {', '.join(settings.fly_apps_to_monitor)}")

    console.print(f"\nnpm: {'✓' if settings.npm_packages_to_monitor else '✗'}")
    if settings.npm_packages_to_monitor:
        console.print(f"  Packages: {', '.join(settings.npm_packages_to_monitor)}")
    if settings.snyk_token:
        console.print("  Snyk: ✓")
    if settings.npm_security_enabled:
        console.print("  Deep Security Analysis: ✓")


@app.command()
def auth(
    service: str = typer.Argument(..., help="Service to authenticate (gh, vercel, fly, snyk)"),
    token: str = typer.Option(
        None, "--token", "-t", help="Token value (if not provided, will prompt)"
    ),
    test: bool = typer.Option(False, "--test", help="Test the token after setting it"),
) -> None:
    """Authenticate with a service by setting API token."""
    service = service.lower()
    valid_services = ["gh", "github", "vercel", "fly", "snyk"]

    if service not in valid_services:
        console.print(f"[bold red]Error: Invalid service '{service}'[/bold red]")
        console.print(f"Valid services: {', '.join(valid_services)}")
        raise typer.Exit(code=1)

    # Get token
    if not token:
        console.print(f"[bold]Setting up {service.upper()} authentication[/bold]")
        token = Prompt.ask(f"Enter your {service.upper()} token", password=True)
        if not token:
            console.print("[bold red]Error: Token cannot be empty[/bold red]")
            raise typer.Exit(code=1)

    # Determine env var name
    env_var_map = {
        "gh": "GITHUB_TOKEN",
        "github": "GITHUB_TOKEN",  # Alias for backwards compatibility
        "vercel": "VERCEL_TOKEN",
        "fly": "FLY_API_TOKEN",
        "snyk": "SNYK_TOKEN",
    }
    env_var = env_var_map[service]

    # Write to .env file
    env_file = Path(".env")
    env_content = ""

    # Read existing .env if it exists
    if env_file.exists():
        env_content = env_file.read_text()

    # Update or add the token
    lines = env_content.split("\n") if env_content else []
    updated = False
    new_lines = []

    for line in lines:
        if line.startswith(f"{env_var}="):
            new_lines.append(f"{env_var}={token}")
            updated = True
        else:
            new_lines.append(line)

    if not updated:
        new_lines.append(f"{env_var}={token}")

    # Write back to .env
    env_file.write_text("\n".join(new_lines) + "\n")

    console.print(f"[bold green]✓[/bold green] {service.upper()} token saved to .env file")

    # Test the token if requested
    if test:
        console.print(f"\n[bold]Testing {service.upper()} token...[/bold]")
        from guardian.cli_helpers import test_service_token

        success, message = asyncio.run(test_service_token(service, token))
        if success:
            console.print(f"[bold green]✓[/bold green] {message}")
        else:
            console.print(f"[bold red]✗[/bold red] {message}")
            console.print("[yellow]Token saved but test failed. Please verify manually.[/yellow]")

    console.print(
        "\n[bold]Note:[/bold] Restart Guardian or reload environment to use the new token."
    )


@app.command()
def mcp() -> None:
    """Start the Guardian MCP server."""
    from guardian.mcp_server import run_mcp_server

    console.print("[bold green]Starting Guardian MCP Server...[/bold green]")
    run_mcp_server()


@app.command()
def auth_status() -> None:
    """Show authentication status for all services."""
    from guardian.cli_helpers import show_auth_status

    settings = get_settings()
    show_auth_status(settings)


@app.command()
def dashboard(
    host: str = typer.Option(None, "--host", help="Host to bind to"),
    port: int = typer.Option(None, "--port", help="Port to bind to"),
) -> None:
    """Start the web dashboard server."""
    settings = get_settings()

    if not settings.dashboard_enabled and not host:
        console.print("[bold yellow]Warning:[/bold yellow] Dashboard is not enabled in config.")
        console.print("Set DASHBOARD_ENABLED=true or use --host/--port to override.")
        console.print()

    if settings.dashboard_api_key:
        console.print("[bold green]✓[/bold green] Dashboard API key configured")
    else:
        console.print(
            "[bold yellow]⚠[/bold yellow] DASHBOARD_API_KEY not set - "
            "dashboard will be accessible without authentication (development mode)"
        )
        console.print("Generate a key with: [dim]openssl rand -hex 32[/dim]")
        console.print()

    console.print("[bold]Starting Guardian dashboard...[/bold]")
    dashboard_url = f"http://{host or settings.dashboard_host}:{port or settings.dashboard_port}"
    console.print(f"Access at: {dashboard_url}")
    console.print()

    try:
        run_dashboard(host=host, port=port)
    except KeyboardInterrupt:
        console.print("\n[bold]Dashboard stopped[/bold]")
        raise typer.Exit(0)

    console.print()


@app.command()
def spec(
    init: bool = typer.Option(False, "--init", help="Create a new spec file interactively"),
    from_env: bool = typer.Option(False, "--from-env", help="Generate spec from current .env"),
    edit: bool = typer.Option(False, "--edit", help="Open spec file in editor"),
) -> None:
    """Manage monitoring specifications."""
    from pathlib import Path

    from guardian.spec import MonitorSpec, get_default_spec, load_spec

    spec_file = Path("guardian.spec.yaml")

    if init:
        if spec_file.exists():
            if not typer.confirm(f"{spec_file} already exists. Overwrite?", default=False):
                console.print("[yellow]Cancelled[/yellow]")
                return

        console.print("[bold]Creating new monitoring spec...[/bold]")
        console.print()

        # Ask basic questions
        name = Prompt.ask("Spec name", default="default")
        description = Prompt.ask("Description (optional)", default="")

        # Ask what to discover
        console.print("\n[bold]What should Guardian discover?[/bold]")
        discover_npm = typer.confirm("  Discover npm packages?", default=True)
        discover_github = typer.confirm("  Discover GitHub repos?", default=True)
        discover_vercel = typer.confirm("  Discover Vercel projects?", default=True)
        discover_fly = typer.confirm("  Discover Fly.io apps?", default=True)
        discover_domains = typer.confirm("  Discover domains from configs?", default=False)
        discover_commits = typer.confirm("  Track GitHub commits?", default=False)
        discover_mentions = typer.confirm("  Track GitHub mentions?", default=False)

        # Build spec
        spec = MonitorSpec(name=name, description=description or None)
        default_spec = get_default_spec()

        # Copy relevant rules
        rule_map = {
            "npm": ["npm_list", "npm_package_json"],
            "github": ["github_repos"],
            "vercel": ["vercel_projects"],
            "fly": ["fly_apps"],
            "domains": ["domains"],
            "commits": ["github_commits"],
            "mentions": ["github_mentions"],
        }

        for key, rule_names in rule_map.items():
            enabled = locals().get(f"discover_{key}", False)
            if enabled:
                for rule_name in rule_names:
                    rule = next(
                        (r for r in default_spec.discovery_rules if r.name == rule_name), None
                    )
                    if rule:
                        spec.discovery_rules.append(rule)

        # Always include username discovery (needed for mentions/commits)
        username_rule = next(
            (r for r in default_spec.discovery_rules if r.name == "github_username"), None
        )
        if username_rule:
            spec.discovery_rules.append(username_rule)

        # Save spec
        import yaml

        spec_dict = spec.model_dump(exclude_none=True)
        with open(spec_file, "w") as f:
            yaml.dump(spec_dict, f, default_flow_style=False, sort_keys=False)

        console.print(f"\n[bold green]✓[/bold green] Created {spec_file}")
        console.print("[dim]Edit it to customize discovery rules[/dim]")

    elif from_env:
        # Generate spec from current .env
        from guardian.config import get_settings

        settings = get_settings()
        spec = MonitorSpec(name="from_env", description="Generated from current .env")

        # Add rules based on what's configured
        default_spec = get_default_spec()

        if settings.npm_packages_to_monitor:
            spec.manual_resources["npm"] = settings.npm_packages_to_monitor
            # Also enable discovery
            spec.discovery_rules.extend(
                [r for r in default_spec.discovery_rules if "npm" in r.name]
            )

        if settings.github_token:
            if settings.github_repos_to_monitor:
                spec.manual_resources["github"] = settings.github_repos_to_monitor
            spec.discovery_rules.extend(
                [r for r in default_spec.discovery_rules if "github" in r.name]
            )

        if settings.vercel_token:
            if settings.vercel_projects_to_monitor:
                spec.manual_resources["vercel"] = settings.vercel_projects_to_monitor
            spec.discovery_rules.extend(
                [r for r in default_spec.discovery_rules if "vercel" in r.name]
            )

        if settings.fly_api_token:
            if settings.fly_apps_to_monitor:
                spec.manual_resources["fly"] = settings.fly_apps_to_monitor
            spec.discovery_rules.extend(
                [r for r in default_spec.discovery_rules if "fly" in r.name]
            )

        # Save
        import yaml

        spec_dict = spec.model_dump(exclude_none=True)
        with open(spec_file, "w") as f:
            yaml.dump(spec_dict, f, default_flow_style=False, sort_keys=False)

        console.print(f"[bold green]✓[/bold green] Generated {spec_file} from current .env")

    elif edit:
        import os
        import subprocess

        editor = os.environ.get("EDITOR", "nano")
        try:
            subprocess.run([editor, str(spec_file)])
        except Exception as e:
            console.print(f"[bold red]Error opening editor: {e}[/bold red]")
            console.print(f"Edit {spec_file} manually")

    else:
        # Show current spec
        if spec_file.exists():
            try:
                spec = load_spec(spec_file)
                console.print(f"[bold blue]Current Spec: {spec.name}[/bold blue]")
                if spec.description:
                    console.print(f"[dim]{spec.description}[/dim]")
                console.print(f"\nDiscovery Rules: {len(spec.discovery_rules)}")
                for rule in spec.discovery_rules:
                    status = "✓" if rule.enabled else "○"
                    console.print(f"  {status} {rule.name} ({rule.type})")
                if spec.manual_resources:
                    console.print("\nManual Resources:")
                    for rtype, resources in spec.manual_resources.items():
                        console.print(f"  {rtype}: {len(resources)} items")
            except Exception as e:
                console.print(f"[bold red]Error loading spec: {e}[/bold red]")
        else:
            console.print(f"[yellow]No spec file found: {spec_file}[/yellow]")
            console.print("Run [bold]guardian spec --init[/bold] to create one")


@app.command()
def discover(
    spec_file: str = typer.Option(
        "guardian.spec.yaml", "--spec", "-s", help="Path to monitoring spec file"
    ),
    base_path: str = typer.Option(
        None, "--base-path", "-b", help="Base path for file scanning (default: ~/Documents/dev)"
    ),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
    update_env: bool = typer.Option(
        False, "--update-env", help="Update .env file with discovered resources"
    ),
    env_file: str = typer.Option(
        ".env",
        "--env-file",
        help="Env file path to write when using --update-env (default: .env).",
    ),
) -> None:
    """Auto-discover resources to monitor based on spec."""
    from pathlib import Path

    from guardian.discovery import discover_all
    from guardian.spec import load_spec

    # Load spec
    spec_path = Path(spec_file)
    if spec_path.exists():
        try:
            spec = load_spec(spec_path)
        except Exception as e:
            console.print(f"[bold red]Error loading spec: {e}[/bold red]")
            raise typer.Exit(1)
    else:
        console.print(f"[bold yellow]Spec file not found: {spec_path}[/bold yellow]")
        console.print("Using default spec...")
        from guardian.spec import get_default_spec

        spec = get_default_spec()

    # Determine base path
    if base_path:
        base = Path(base_path)
    else:
        base = Path.home() / "Documents" / "dev"

    console.print(f"[bold]Discovering resources from: {base}[/bold]")
    console.print(f"[dim]Using spec: {spec.name}[/dim]\n")

    async def run_discovery():
        result = await discover_all(spec, base)
        return result

    result = asyncio.run(run_discovery())

    if json_output:
        console.print(json.dumps(result.to_dict(), indent=2))
    else:
        # Display results
        from rich.table import Table

        console.print("[bold blue]Discovery Results[/bold blue]\n")

        if result.resources:
            table = Table(title="Discovered Resources")
            table.add_column("Type", style="cyan")
            table.add_column("Count", style="magenta")
            table.add_column("Examples", style="green")

            for resource_type, resources in result.resources.items():
                count = len(resources)
                examples = ", ".join(str(r)[:50] for r in resources[:3])
                if count > 3:
                    examples += f" ... (+{count - 3} more)"
                table.add_row(resource_type, str(count), examples)

            console.print(table)
            console.print()

        if result.errors:
            console.print("[bold red]Errors:[/bold red]")
            for error in result.errors:
                console.print(f"  • {error}")
            console.print()

        # Update .env if requested
        if update_env:
            env_path = Path(env_file)
            env_content = env_path.read_text() if env_path.exists() else ""

            # Update npm packages
            if "npm" in result.resources:
                npm_packages = result.resources["npm"]
                env_content = _update_env_var(
                    env_content, "NPM_PACKAGES_TO_MONITOR", ",".join(npm_packages[:20])
                )

            # Update GitHub repos
            if "github" in result.resources:
                github_repos = result.resources["github"]
                env_content = _update_env_var(
                    env_content, "GITHUB_REPOS_TO_MONITOR", ",".join(github_repos[:20])
                )

            # Update Vercel projects
            if "vercel" in result.resources:
                vercel_projects = result.resources["vercel"]
                env_content = _update_env_var(
                    env_content, "VERCEL_PROJECTS_TO_MONITOR", ",".join(vercel_projects[:20])
                )

            # Update Fly apps
            if "fly" in result.resources:
                fly_apps = result.resources["fly"]
                env_content = _update_env_var(
                    env_content, "FLY_APPS_TO_MONITOR", ",".join(fly_apps[:20])
                )

            env_path.write_text(env_content)
            console.print("[bold green]✓[/bold green] Updated .env file with discovered resources")


@app.command()
def stats(
    live_mode: bool = typer.Option(
        False, "--live", "-l", help="Live updating stats (refresh every 5s)"
    ),
) -> None:
    """Show current monitoring statistics in a TUI."""
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table

    console = Console()

    def generate_stats() -> Layout:
        """Generate the stats layout."""
        settings = get_settings()
        guardian = Guardian(settings)

        # Run checks to get current stats
        import asyncio

        report = asyncio.run(guardian.run_checks())

        # Create layout
        layout = Layout()

        # Header
        header = Panel.fit(
            "[bold blue]🛡️ Guardian Monitoring Stats[/bold blue]",
            border_style="blue",
        )

        # Summary table
        summary_table = Table(show_header=False, box=None, padding=(0, 2))
        summary_table.add_column("Metric", style="cyan", width=25)
        summary_table.add_column("Value", style="magenta")

        summary = report.summary
        summary_table.add_row("Total Checks", str(summary.get("total_checks", 0)))
        summary_table.add_row("Successful", f"[green]{summary.get('successful_checks', 0)}[/green]")
        summary_table.add_row("Failed", f"[red]{summary.get('failed_checks', 0)}[/red]")
        summary_table.add_row("", "")
        summary_table.add_row("Vulnerabilities", str(summary.get("total_vulnerabilities", 0)))
        summary_table.add_row(
            "Critical", f"[red]{summary.get('critical_vulnerabilities', 0)}[/red]"
        )
        summary_table.add_row(
            "Unhealthy Deployments", f"[yellow]{summary.get('unhealthy_deployments', 0)}[/yellow]"
        )
        summary_table.add_row("Repository Alerts", str(summary.get("open_repository_alerts", 0)))
        summary_table.add_row("", "")
        summary_table.add_row(
            "Total Cost (USD)",
            f"[bold yellow]${summary.get('total_cost_usd', 0):.2f}[/bold yellow]",
        )

        summary_panel = Panel(summary_table, title="Summary", border_style="blue")

        # Checks table
        checks_table = Table(title="Check Results")
        checks_table.add_column("Service", style="cyan")
        checks_table.add_column("Status", style="magenta")
        checks_table.add_column("Vulns", justify="right")
        checks_table.add_column("Deployments", justify="right")
        checks_table.add_column("Cost", justify="right", style="yellow")

        for check in report.checks:
            status_icon = "[green]✓[/green]" if check.success else "[red]✗[/red]"
            vuln_count = len(check.vulnerabilities)
            deploy_count = len(check.deployments)
            cost = sum(cm.amount or 0 for cm in check.cost_metrics)
            cost_str = f"${cost:.2f}" if cost > 0 else "-"

            checks_table.add_row(
                check.check_type.upper(),
                status_icon,
                str(vuln_count),
                str(deploy_count),
                cost_str,
            )

        checks_panel = Panel(checks_table, title="Service Checks", border_style="green")

        # Cost breakdown
        cost_table = Table(title="Cost Breakdown", show_header=False, box=None)
        cost_table.add_column("Service", style="cyan")
        cost_table.add_column("Amount", justify="right", style="yellow")
        cost_table.add_column("Usage", style="green")

        all_cost_metrics = report.get_cost_metrics()
        if all_cost_metrics:
            for cm in all_cost_metrics:
                amount_str = f"${cm.amount:.2f}" if cm.amount else "$0.00"
                usage_str = f"{cm.usage:.0f}/{cm.limit:.0f}" if cm.limit else f"{cm.usage:.0f}"
                usage_pct = f"({cm.usage_percent:.1f}%)" if cm.usage_percent else ""
                cost_table.add_row(cm.service, amount_str, f"{usage_str} {usage_pct}")
        else:
            cost_table.add_row("No cost data", "-", "-")

        cost_panel = Panel(cost_table, title="Cost Metrics", border_style="yellow")

        # Layout structure
        layout.split_column(
            Layout(header, size=3),
            Layout(summary_panel, name="summary"),
            Layout(checks_panel, name="checks"),
            Layout(cost_panel, name="costs"),
        )

        layout["summary"].size = 12
        layout["checks"].size = None
        layout["costs"].size = None

        return layout

    if live_mode:
        # Live updating mode
        with Live(generate_stats(), refresh_per_second=0.2, screen=True) as live_view:
            import time

            while True:
                try:
                    time.sleep(5)
                    live_view.update(generate_stats())
                except KeyboardInterrupt:
                    break
    else:
        # Single snapshot
        console.print(generate_stats())


@app.command("sweep-dev")
def sweep_dev(
    dev_root: str = typer.Option(
        None,
        "--dev-root",
        help="Dev workspace root (default: $DEV_DIR or ~/Documents/dev).",
    ),
    output: str = typer.Option(
        "guardian_sweep_dev.json",
        "--output",
        "-o",
        help="Where to write the JSON report.",
    ),
    max_blob_mb: int = typer.Option(
        5,
        "--max-blob-mb",
        help="Flag tracked files larger than this many MiB (working tree size).",
    ),
    max_depth: int = typer.Option(
        2,
        "--max-depth",
        help="How deep under dev_root to look for git repos (bounded).",
    ),
) -> None:
    """Sweep local dev repos for likely accidental committed artifacts."""
    from guardian.sweeps.local_dev import default_dev_root, sweep_dev_repos, write_report

    root = Path(dev_root).expanduser() if dev_root else default_dev_root()
    report_path = Path(output).expanduser()

    hits, meta = sweep_dev_repos(
        root,
        max_blob_bytes=max_blob_mb * 1024 * 1024,
        max_depth=max_depth,
    )
    write_report(report_path, hits, meta)

    console.print(f"[bold]Wrote report:[/bold] {report_path}")
    console.print(f"[bold]Repos scanned:[/bold] {meta['repos_scanned']}")
    console.print(f"[bold]Findings:[/bold] {len(hits)}")

    if hits:
        console.print(
            "[bold yellow]Action:[/bold yellow] Review report and clean up flagged files."
        )
        raise typer.Exit(code=2)


@app.command()
def sweep(
    spec_file: str = typer.Option(
        "guardian.spec.yaml",
        "--spec",
        "-s",
        help="Path to spec file (drives which sweeps run and their policy).",
    ),
    dev_root: str = typer.Option(
        None,
        "--dev-root",
        help="Dev workspace root (default: $DEV_DIR or ~/Documents/dev).",
    ),
    only: list[str] = typer.Option(
        None,
        "--only",
        help="Run only these sweeps (repeatable). Known: local_dev, public_github_secrets, local_dirty_worktree_secrets, project_flaudit, gitignore_audit, dependency_audit, ssh_key_audit, cargo_publish_audit, ai_editor_config_audit",
    ),
) -> None:
    """Run spec-driven sweeps (policy checks).

    Today this runs the local dev repo sweep (and will expand over time).
    """
    from guardian.spec import MonitorSpec, SweepSpec, load_spec
    from guardian.sweeps.local_dev import DEFAULT_DENY_GLOBS, default_dev_root, sweep_dev_repos
    from guardian.sweeps.local_dirty_worktree_secrets import (
        scan_dirty_worktrees,
    )
    from guardian.sweeps.local_dirty_worktree_secrets import (
        write_report as write_dirty_json,
    )
    from guardian.sweeps.public_github_secrets import scan_public_github_repos
    from guardian.sweeps.public_github_secrets import write_report as write_json

    spec_path = Path(spec_file)
    if not spec_path.exists():
        console.print("No spec file found; using defaults. Create guardian.spec.yaml to customize.")
        spec = MonitorSpec(
            name="default",
            discovery_rules=[],
            manual_resources={},
            filters={},
            sweeps=SweepSpec(),
        )
    else:
        spec = load_spec(spec_path)

    wanted = {w.strip() for w in (only or []) if w and w.strip()}

    exit_code = 0

    # local-dev sweep
    local = spec.sweeps.local_dev
    if local.enabled and (not wanted or "local_dev" in wanted):
        root = Path(dev_root).expanduser() if dev_root else default_dev_root()
        deny = list(DEFAULT_DENY_GLOBS) + list(local.deny_globs or [])
        hits, meta = sweep_dev_repos(
            root,
            deny_globs=deny,
            max_blob_bytes=local.max_blob_mb * 1024 * 1024,
            max_depth=local.max_depth,
        )
        out_path = Path(local.output).expanduser()
        from guardian.sweeps.local_dev import write_report

        write_report(out_path, hits, meta)
        console.print(f"[bold]local_dev report:[/bold] {out_path}")
        console.print(f"[bold]Repos scanned:[/bold] {meta['repos_scanned']}")
        console.print(f"[bold]Findings:[/bold] {len(hits)}")
        if hits:
            exit_code = max(exit_code, 2)

    # public-github-secrets sweep
    pub = spec.sweeps.public_github_secrets
    if pub.enabled and (not wanted or "public_github_secrets" in wanted):
        report, errors = scan_public_github_repos(
            owners=pub.owners,
            include_repos=pub.include_repos,
            exclude_repos=pub.exclude_repos,
            include_forks=pub.include_forks,
            max_repos=pub.max_repos,
            engines=getattr(pub, "engines", None),
            timeout_s=pub.timeout_s,
            max_concurrency=pub.max_concurrency,
        )
        out_path = Path(pub.output).expanduser()
        write_json(out_path, report)
        console.print(f"[bold]public_github_secrets report:[/bold] {out_path}")
        console.print(f"[bold]Repos scanned:[/bold] {report['scope']['repos_scanned_count']}")
        console.print(f"[bold]Findings:[/bold] {report['summary']['findings_total']}")
        if errors:
            console.print(f"[yellow]Errors:[/yellow] {len(errors)} (see report)")
            if pub.fail_on_errors:
                console.print(
                    "[bold red]Action:[/bold red] Fix scan errors (missed coverage) and rerun."
                )
                exit_code = max(exit_code, 3)
        if report["summary"]["findings_total"] > 0:
            exit_code = max(exit_code, 2)

    # local dirty worktree secret sweep
    dirty = spec.sweeps.local_dirty_worktree_secrets
    if dirty.enabled and (not wanted or "local_dirty_worktree_secrets" in wanted):
        root = Path(dirty.dev_root).expanduser() if dirty.dev_root else default_dev_root()
        report, errors = scan_dirty_worktrees(
            dev_root=root,
            max_depth=dirty.max_depth,
            only_dirty=dirty.only_dirty,
            exclude_repo_globs=dirty.exclude_repo_globs,
            check_upstream=dirty.check_upstream,
            fetch_remotes=dirty.fetch_remotes,
            max_paths_per_repo=getattr(dirty, "max_paths_per_repo", 50),
            include_ignored_files=getattr(dirty, "include_ignored_files", False),
            max_concurrency=dirty.max_concurrency,
            timeout_s=dirty.timeout_s,
        )
        out_path = Path(dirty.output).expanduser()
        write_dirty_json(out_path, report)
        console.print(f"[bold]local_dirty_worktree_secrets report:[/bold] {out_path}")
        console.print(f"[bold]Repos scanned:[/bold] {report['scope']['repos_scanned_count']}")
        console.print(f"[bold]Findings:[/bold] {report['summary']['findings_total']}")
        if errors:
            console.print(f"[yellow]Errors:[/yellow] {len(errors)} (see report)")
        if report["summary"]["findings_total"] > 0:
            exit_code = max(exit_code, 2)

    # project_flaudit sweep (files-to-prompt + OpenRouter/Gemini)
    flaudit = spec.sweeps.project_flaudit
    if flaudit.enabled and (not wanted or "project_flaudit" in wanted):
        from guardian.sweeps.local_dev import default_dev_root
        from guardian.sweeps.project_flaudit import scan_project_flaudit
        from guardian.sweeps.project_flaudit import write_report as write_flaudit

        root = Path(flaudit.dev_root).expanduser() if flaudit.dev_root else default_dev_root()
        settings = get_settings()
        wr_path = None
        if flaudit.workspace_rules_path:
            p = Path(flaudit.workspace_rules_path).expanduser()
            if not p.is_absolute():
                p = root / p
            wr_path = str(p.resolve()) if p.resolve().is_dir() else None
        results, meta = scan_project_flaudit(
            dev_root=root,
            k_recent=flaudit.k_recent,
            max_depth=flaudit.max_depth,
            model_id=flaudit.model_id,
            settings=settings,
            max_prompt_chars=flaudit.max_prompt_chars,
            include_rules=flaudit.include_rules,
            exclude_repo_globs=flaudit.exclude_repo_globs,
            workspace_rules_path=wr_path,
            workspace_rules_include=flaudit.workspace_rules_include or None,
            max_workspace_rules_chars=flaudit.max_workspace_rules_chars,
            severity_guidance=flaudit.severity_guidance,
            depth_0_skip_prefixes=flaudit.depth_0_skip_prefixes,
            depth_0_allow_names=flaudit.depth_0_allow_names,
            scope_recent_commits=flaudit.scope_recent_commits,
            public_repo_names=flaudit.public_repo_names or None,
            stricter_public_prompt=flaudit.stricter_public_prompt,
        )
        out_path = Path(flaudit.output).expanduser()
        write_flaudit(out_path, results, meta)
        console.print(f"[bold]project_flaudit report:[/bold] {out_path}")
        console.print(f"[bold]Projects analyzed:[/bold] {meta['repos_scanned']}")
        total_findings = sum(len(r.findings) for r in results)
        total_errors = sum(1 for r in results if r.error)
        console.print(f"[bold]Findings:[/bold] {total_findings}")
        if total_errors:
            console.print(f"[bold]Errors:[/bold] {total_errors}", style="yellow")
        if total_findings > 0:
            exit_code = max(exit_code, 2)

    # gitignore audit sweep
    gi = spec.sweeps.gitignore_audit
    if gi.enabled and (not wanted or "gitignore_audit" in wanted):
        from guardian.sweeps.gitignore_audit import audit_gitignores
        from guardian.sweeps.gitignore_audit import write_report as write_gi

        root = Path(gi.dev_root).expanduser() if gi.dev_root else default_dev_root()
        report, errors = audit_gitignores(
            dev_root=root,
            max_depth=gi.max_depth,
            exclude_repo_globs=gi.exclude_repo_globs,
        )
        out_path = Path(gi.output).expanduser()
        write_gi(out_path, report)
        console.print(f"[bold]gitignore_audit report:[/bold] {out_path}")
        console.print(f"[bold]Repos scanned:[/bold] {report['scope']['repos_scanned']}")
        console.print(
            f"[bold]Repos without .gitignore:[/bold] {report['summary']['repos_without_gitignore']}"
        )
        console.print(
            f"[bold]Public repos with gaps:[/bold] {report['summary']['public_repos_with_gaps']}"
        )
        console.print(f"[bold]Total gaps:[/bold] {report['summary']['total_gaps']}")
        if errors:
            console.print(f"[yellow]Errors:[/yellow] {len(errors)} (see report)")
        if report["summary"]["public_repos_with_gaps"] > 0:
            exit_code = max(exit_code, 2)

    # dependency audit sweep
    depaudit = spec.sweeps.dependency_audit
    if depaudit.enabled and (not wanted or "dependency_audit" in wanted):
        from guardian.sweeps.dependency_audit import audit_dependencies
        from guardian.sweeps.dependency_audit import write_report as write_depaudit

        root = Path(depaudit.dev_root).expanduser() if depaudit.dev_root else default_dev_root()
        report, errors = audit_dependencies(
            dev_root=root,
            max_depth=depaudit.max_depth,
            exclude_repo_globs=depaudit.exclude_repo_globs,
            engines=depaudit.engines,
            max_concurrency=depaudit.max_concurrency,
            timeout_s=depaudit.timeout_s,
        )
        out_path = Path(depaudit.output).expanduser()
        write_depaudit(out_path, report)
        console.print(f"[bold]dependency_audit report:[/bold] {out_path}")
        console.print(f"[bold]Repos scanned:[/bold] {report['scope']['repos_scanned']}")
        console.print(f"[bold]Repos with vulns:[/bold] {report['summary']['repos_with_vulns']}")
        console.print(f"[bold]Total vulns:[/bold] {report['summary']['total_vulns']}")
        sev = report["summary"]["severity_counts"]
        console.print(
            f"[bold]Severity:[/bold] critical={sev.get('critical', 0)} high={sev.get('high', 0)} medium={sev.get('medium', 0)} low={sev.get('low', 0)}"
        )
        if errors:
            console.print(f"[yellow]Errors:[/yellow] {len(errors)} (see report)")
        if report["summary"]["total_vulns"] > 0:
            exit_code = max(exit_code, 2)

    # ssh key audit sweep
    sshk = spec.sweeps.ssh_key_audit
    if sshk.enabled and (not wanted or "ssh_key_audit" in wanted):
        from guardian.sweeps.ssh_key_audit import audit_ssh_keys
        from guardian.sweeps.ssh_key_audit import write_report as write_sshk

        ssh_path = Path(sshk.ssh_dir).expanduser()
        report, errors = audit_ssh_keys(
            ssh_dir=ssh_path,
            check_github=sshk.check_github,
            min_rsa_bits=sshk.min_rsa_bits,
            flag_ecdsa=sshk.flag_ecdsa,
        )
        out_path = Path(sshk.output).expanduser()
        write_sshk(out_path, report)
        console.print(f"[bold]ssh_key_audit report:[/bold] {out_path}")
        console.print(f"[bold]Keys scanned:[/bold] {report['summary']['keys_scanned']}")
        console.print(f"[bold]Issues:[/bold] {report['summary']['issues_total']}")
        if errors:
            console.print(f"[yellow]Errors:[/yellow] {len(errors)} (see report)")
        if report["summary"]["issues_total"] > 0:
            exit_code = max(exit_code, 2)

    # cargo publish audit sweep
    cpub = spec.sweeps.cargo_publish_audit
    if cpub.enabled and (not wanted or "cargo_publish_audit" in wanted):
        from guardian.sweeps.cargo_publish_audit import audit_cargo_publish
        from guardian.sweeps.cargo_publish_audit import write_report as write_cpub

        root = Path(cpub.dev_root).expanduser() if cpub.dev_root else default_dev_root()
        report, errors = audit_cargo_publish(
            dev_root=root,
            max_depth=cpub.max_depth,
            exclude_repo_globs=cpub.exclude_repo_globs,
            only_public=cpub.only_public,
            repo_names=cpub.repo_names or None,
        )
        out_path = Path(cpub.output).expanduser()
        write_cpub(out_path, report)
        console.print(f"[bold]cargo_publish_audit report:[/bold] {out_path}")
        console.print(f"[bold]Rust repos found:[/bold] {report['scope']['rust_repos_found']}")
        console.print(f"[bold]Repos with errors:[/bold] {report['summary']['repos_with_errors']}")
        console.print(
            f"[bold]Repos with warnings:[/bold] {report['summary']['repos_with_warnings']}"
        )
        console.print(f"[bold]Total findings:[/bold] {report['summary']['total_findings']}")
        if report["summary"]["repos_with_errors_list"]:
            console.print(
                f"[red]Error repos:[/red] {', '.join(report['summary']['repos_with_errors_list'])}"
            )
        if errors:
            console.print(f"[yellow]Errors:[/yellow] {len(errors)} (see report)")
        if report["summary"]["total_errors"] > 0:
            exit_code = max(exit_code, 2)

    # ai editor config audit sweep
    aicfg = spec.sweeps.ai_editor_config_audit
    if aicfg.enabled and (not wanted or "ai_editor_config_audit" in wanted):
        from guardian.sweeps.ai_editor_config_audit import audit_ai_editor_configs
        from guardian.sweeps.ai_editor_config_audit import write_report as write_aicfg

        root = Path(aicfg.dev_root).expanduser() if aicfg.dev_root else default_dev_root()
        report, errors = audit_ai_editor_configs(
            dev_root=root,
            max_depth=aicfg.max_depth,
            exclude_repo_globs=aicfg.exclude_repo_globs,
            only_with_configs=aicfg.only_with_configs,
        )
        out_path = Path(aicfg.output).expanduser()
        write_aicfg(out_path, report)
        console.print(f"[bold]ai_editor_config_audit report:[/bold] {out_path}")
        console.print(
            f"[bold]Repos with AI configs:[/bold] {report['scope']['repos_with_ai_configs']}"
        )
        console.print(f"[bold]Repos with errors:[/bold] {report['summary']['repos_with_errors']}")
        console.print(
            f"[bold]Repos with warnings:[/bold] {report['summary']['repos_with_warnings']}"
        )
        console.print(f"[bold]Total findings:[/bold] {report['summary']['total_findings']}")
        if report["summary"].get("tool_adoption"):
            tools = ", ".join(f"{t}={c}" for t, c in report["summary"]["tool_adoption"])
            console.print(f"[bold]Tool adoption:[/bold] {tools}")
        if errors:
            console.print(f"[yellow]Errors:[/yellow] {len(errors)} (see report)")
        if report["summary"]["total_errors"] > 0:
            exit_code = max(exit_code, 2)

    any_enabled = (
        local.enabled
        or pub.enabled
        or spec.sweeps.local_dirty_worktree_secrets.enabled
        or spec.sweeps.project_flaudit.enabled
        or spec.sweeps.gitignore_audit.enabled
        or spec.sweeps.dependency_audit.enabled
        or spec.sweeps.ssh_key_audit.enabled
        or spec.sweeps.cargo_publish_audit.enabled
        or spec.sweeps.ai_editor_config_audit.enabled
    )
    if not wanted and not any_enabled:
        console.print("[yellow]No sweeps enabled in spec.[/yellow]")

    if exit_code > 0:
        raise typer.Exit(code=exit_code)


def _update_env_var(env_content: str, var_name: str, value: str) -> str:
    """Update or add an environment variable in .env content."""
    lines = env_content.split("\n")
    updated = False
    new_lines = []

    for line in lines:
        if line.startswith(f"{var_name}="):
            new_lines.append(f"{var_name}={value}")
            updated = True
        else:
            new_lines.append(line)

    if not updated:
        new_lines.append(f"{var_name}={value}")

    return "\n".join(new_lines) + "\n"


@app.command()
def doctor() -> None:
    """Check external tool prerequisites for sweeps."""
    import shutil

    tools = [
        (
            "trufflehog",
            "public_github_secrets, local_dirty_worktree_secrets",
            "brew install trufflehog",
        ),
        (
            "cargo-audit",
            "dependency_audit (Rust repos)",
            "cargo install cargo-audit",
        ),
        (
            "npm",
            "dependency_audit (JS repos)",
            "install Node.js from https://nodejs.org",
        ),
        (
            "pip-audit",
            "dependency_audit (Python repos)",
            "pip install pip-audit",
        ),
        (
            "gh",
            "public_github_secrets, ssh_key_audit (GitHub cross-ref)",
            "brew install gh",
        ),
        (
            "git",
            "most sweeps",
            "brew install git",
        ),
    ]

    found = 0
    total = len(tools)

    table = Table(show_header=True, header_style="bold")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Used by")
    table.add_column("Install hint")

    for tool_name, used_by, hint in tools:
        path = shutil.which(tool_name)
        if path:
            found += 1
            table.add_row(tool_name, "[green]found[/green]", used_by, "")
        else:
            table.add_row(tool_name, "[red]missing[/red]", used_by, hint)

    console.print(table)
    console.print()
    console.print(
        f"{found}/{total} tools found. Missing tools will cause some sweeps to skip or fail."
    )


def main() -> None:
    """Entry point for CLI."""
    app()


if __name__ == "__main__":
    main()
