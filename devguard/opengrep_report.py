"""Summarize explicit OpenGrep JSON outputs without running repository code."""

import json
import stat
from pathlib import Path

import typer


def summarize_report(path: Path, expected_version: str | None = None) -> dict:
    """Describe coverage of one artifact, including findings from a partial scan."""
    report = {"path": str(path), "status": "invalid"}
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            return {**report, "status": "unreadable"}
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {**report, "status": "missing"}
    except OSError:
        return {**report, "status": "unreadable"}
    except (ValueError, RecursionError):
        return report

    if not isinstance(data, dict):
        return report
    version = data.get("version")
    results = data.get("results")
    errors = data.get("errors")
    paths = data.get("paths")
    scanned = paths.get("scanned") if isinstance(paths, dict) else None
    skipped_rules = data.get("skipped_rules", [])
    if not (
        isinstance(version, str)
        and version.strip()
        and isinstance(results, list)
        and all(
            isinstance(r, dict) and isinstance(r.get("check_id"), str) and r["check_id"]
            for r in results
        )
        and isinstance(errors, list)
        and isinstance(scanned, list)
        and all(isinstance(p, str) and p for p in scanned)
        and isinstance(skipped_rules, list)
    ):
        return report
    if expected_version is not None and version != expected_version:
        status = "version_mismatch"
    elif errors or skipped_rules:
        status = "partial"
    elif not scanned:
        status = "no_targets"
    elif results:
        status = "findings"
    else:
        status = "clean"
    return {
        "path": str(path),
        "status": status,
        "version": version,
        "scanned_files": len(scanned),
        "findings": len(results),
        "errors": len(errors),
        "skipped_rules": len(skipped_rules),
    }


def opengrep_report(
    paths: list[Path] = typer.Argument(..., help="Each expected OpenGrep JSON report path."),
    expect_version: str | None = typer.Option(None, help="Require this exact reported version."),
) -> None:
    """Read existing OpenGrep artifacts and distinguish incomplete coverage from clean scans."""
    reports = [summarize_report(path, expect_version) for path in paths]
    typer.echo(json.dumps({"reports": reports}, indent=2))
    if any(r["status"] not in ("clean", "findings") for r in reports):
        raise typer.Exit(3)
    if any(r["status"] == "findings" for r in reports):
        raise typer.Exit(2)
