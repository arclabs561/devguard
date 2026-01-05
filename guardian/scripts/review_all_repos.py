#!/usr/bin/env python3
"""Comprehensive review of all repos and npm packages."""

import asyncio
import json
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.table import Table

# Import Guardian discovery
import sys

guardian_path = Path(__file__).parent.parent.parent
sys.path.insert(0, str(guardian_path))
from guardian.discovery import discover_all
from guardian.spec import load_spec, get_default_spec

# Import npm security analysis
from guardian.scripts.redteam_npm_packages import analyze_package

console = Console()


async def discover_github_repos() -> list[str]:
    """Discover all GitHub repositories."""
    repos = []
    try:
        result = subprocess.run(
            ["gh", "repo", "list", "--json", "nameWithOwner", "--limit", "1000"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            repos = [repo["nameWithOwner"] for repo in data]
    except Exception as e:
        console.print(f"[yellow]Warning: Could not discover GitHub repos: {e}[/yellow]")
    return repos


async def discover_npm_packages_from_dev(base_path: Path) -> list[dict[str, str]]:
    """Discover npm packages in dev directory."""
    packages = []
    try:
        # Use a more efficient approach - scan top-level directories first
        console.print("    [dim]Scanning directories...[/dim]")
        dirs_scanned = 0
        for item in base_path.iterdir():
            if not item.is_dir():
                continue
            dirs_scanned += 1
            if dirs_scanned % 10 == 0:
                console.print(f"    [dim]Scanned {dirs_scanned} directories...[/dim]")

            # Check for package.json in this directory
            package_json = item / "package.json"
            if package_json.exists():
                try:
                    with open(package_json) as f:
                        pkg_data = json.load(f)
                        name = pkg_data.get("name")
                        version = pkg_data.get("version", "unknown")
                        if name:
                            packages.append(
                                {
                                    "name": name,
                                    "version": version,
                                    "path": str(item.name),
                                }
                            )
                except Exception:
                    pass

            # Also check one level deeper for nested packages
            for subdir in item.iterdir():
                if subdir.is_dir():
                    sub_package_json = subdir / "package.json"
                    if sub_package_json.exists():
                        try:
                            with open(sub_package_json) as f:
                                pkg_data = json.load(f)
                                name = pkg_data.get("name")
                                version = pkg_data.get("version", "unknown")
                                if name:
                                    packages.append(
                                        {
                                            "name": name,
                                            "version": version,
                                            "path": f"{item.name}/{subdir.name}",
                                        }
                                    )
                        except Exception:
                            pass
    except Exception as e:
        console.print(f"[yellow]Warning: Error scanning dev directory: {e}[/yellow]")
    return packages


async def discover_published_npm_packages(packages: list[dict]) -> list[dict]:
    """Check which packages are published to npm."""
    published = []
    async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=5.0)) as client:
        for pkg in packages:
            name = pkg["name"]
            try:
                # Check if package exists on npm
                encoded_name = name.replace("/", "%2F")
                response = await asyncio.wait_for(
                    client.get(f"https://registry.npmjs.org/{encoded_name}"),
                    timeout=5.0,
                )
                if response.status_code == 200:
                    data = response.json()
                    dist_tags = data.get("dist-tags", {})
                    latest = dist_tags.get("latest", pkg.get("version", "unknown"))
                    published.append(
                        {
                            "name": name,
                            "version": latest,
                            "path": pkg.get("path", ""),
                        }
                    )
            except (asyncio.TimeoutError, httpx.TimeoutException):
                console.print(f"    [yellow]Timeout checking {name}[/yellow]")
            except Exception as e:
                console.print(f"    [yellow]Error checking {name}: {e}[/yellow]")
    return published


async def review_repos():
    """Main review function."""
    console.print("[bold blue]🔍 Comprehensive Repository Review[/bold blue]\n")

    base_path = Path.home() / "Documents" / "dev"

    # Step 1: Discover GitHub repos
    console.print("[cyan]Step 1: Discovering GitHub repositories...[/cyan]")
    github_repos = await discover_github_repos()
    console.print(f"  Found {len(github_repos)} GitHub repositories")

    # Step 2: Discover npm packages in dev directory
    console.print(f"\n[cyan]Step 2: Scanning {base_path} for npm packages...[/cyan]")
    local_packages = await discover_npm_packages_from_dev(base_path)
    console.print(f"  Found {len(local_packages)} npm packages locally")

    # Step 3: Check which are published
    console.print("\n[cyan]Step 3: Checking which packages are published to npm...[/cyan]")
    console.print(f"  [dim]Checking {len(local_packages)} packages...[/dim]")
    published_packages = await discover_published_npm_packages(local_packages)

    # Remove duplicates by package name
    seen = set()
    unique_packages = []
    for pkg in published_packages:
        if pkg["name"] not in seen:
            seen.add(pkg["name"])
            unique_packages.append(pkg)
    published_packages = unique_packages

    console.print(f"  Found {len(published_packages)} published packages")

    # Step 4: Run security analysis on published packages
    if published_packages:
        console.print("\n[cyan]Step 4: Running security analysis on published packages...[/cyan]")
        console.print(
            f"  [dim]Analyzing {min(len(published_packages), 10)} packages (limited to 10 for performance)...[/dim]"
        )
        results = []

        for i, pkg in enumerate(published_packages[:10], 1):  # Limit to first 10 for now
            name = pkg["name"]
            version = pkg.get("version")
            console.print(f"  [{i}/10] Analyzing {name}@{version}...")
            try:
                # Add timeout to prevent hanging
                result = await asyncio.wait_for(
                    analyze_package(name, version),
                    timeout=120.0,  # 2 minute timeout per package
                )
                results.append(
                    {
                        "package": name,
                        "version": version,
                        "path": pkg.get("path", ""),
                        "result": result,
                    }
                )
                console.print(f"    [green]✓ Completed[/green]")
            except asyncio.TimeoutError:
                console.print(f"    [red]✗ Timeout after 2 minutes[/red]")
                results.append(
                    {
                        "package": name,
                        "version": version,
                        "path": pkg.get("path", ""),
                        "error": "Timeout after 2 minutes",
                    }
                )
            except Exception as e:
                console.print(f"    [red]✗ Error: {e}[/red]")
                results.append(
                    {
                        "package": name,
                        "version": version,
                        "path": pkg.get("path", ""),
                        "error": str(e),
                    }
                )

        # Display summary
        console.print("\n[bold]📊 Security Analysis Summary[/bold]\n")

        table = Table(title="Published Packages Security Review")
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="magenta")
        table.add_column("Secrets", justify="right")
        table.add_column("Sensitive Files", justify="right")
        table.add_column("Obfuscated Code", justify="right")
        table.add_column("Git History", justify="right")
        table.add_column("Status", style="green")

        for result in results:
            if "error" in result:
                table.add_row(
                    result["package"],
                    result.get("version", "?"),
                    "-",
                    "-",
                    "-",
                    "-",
                    "[red]Error[/red]",
                )
            else:
                findings = result.get("result", {}).get("findings", {})
                secrets = len(findings.get("secrets", []))
                sensitive_files = len(findings.get("sensitive_files", []))
                obfuscated = len(findings.get("obfuscated_code", []))
                git_history = "Yes" if findings.get("git_history") else "No"

                status = "[green]✓[/green]"
                if secrets > 0 or sensitive_files > 0 or findings.get("git_history"):
                    status = "[red]⚠[/red]"

                table.add_row(
                    result["package"],
                    result.get("version", "?"),
                    str(secrets),
                    str(sensitive_files),
                    str(obfuscated),
                    git_history,
                    status,
                )

        console.print(table)

        # Save detailed results
        output_file = Path("repo_review_results.json")
        with open(output_file, "w") as f:
            json.dump(
                {
                    "github_repos": github_repos,
                    "local_packages": local_packages,
                    "published_packages": published_packages,
                    "security_results": results,
                },
                f,
                indent=2,
            )
        console.print(f"\n[green]✓[/green] Detailed results saved to {output_file}")

    # Summary
    console.print("\n[bold]📋 Review Summary[/bold]")
    console.print(f"  GitHub Repositories: {len(github_repos)}")
    console.print(f"  Local npm Packages: {len(local_packages)}")
    console.print(f"  Published Packages: {len(published_packages)}")

    if published_packages:
        console.print("\n[bold yellow]💡 Next Steps:[/bold yellow]")
        console.print("  1. Review security findings in the table above")
        console.print("  2. Check detailed results in repo_review_results.json")
        console.print("  3. Run: uv run python guardian/scripts/generate_npmignore.py")
        console.print("  4. Fix any critical issues before next publish")


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    console.print("\n[yellow]Interrupted by user. Exiting...[/yellow]")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    try:
        asyncio.run(review_repos())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted. Exiting...[/yellow]")
        sys.exit(0)
