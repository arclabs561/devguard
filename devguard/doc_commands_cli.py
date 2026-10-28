"""Explicit, advisory documentation checks without sweep discovery or execution."""

import json
from pathlib import Path

import typer

from devguard.sweeps.doc_commands import check_doc_commands


def doc_commands(
    repo: Path = typer.Option(..., "--repo", help="Admitted local repository directory."),
    document: list[str] = typer.Option(
        ..., "--document", help="Markdown path relative to repo; repeat for each admitted file."
    ),
    package_root: str = typer.Option(
        ..., "--package-root", help="Assumed command working directory relative to repo."
    ),
) -> None:
    """Report missing npm scripts/Cargo examples as JSON; never execute commands.

    Findings are advisory (exit 0). Skipped checks or input errors exit 3.
    Only explicit inputs are read; no report files are written.
    """
    try:
        report = check_doc_commands(repo.expanduser(), document, package_root=package_root)
    except (OSError, ValueError, RuntimeError):
        # Exception text can contain rejected paths or manifest contents.
        report = {
            "findings": [],
            "skipped": [],
            "commands_checked": 0,
            "errors": ["Unavailable or unsafe repository/package scope"],
        }
    else:
        report["errors"] = []
    typer.echo(json.dumps(report, indent=2))
    if report["errors"] or report["skipped"]:
        raise typer.Exit(code=3)
