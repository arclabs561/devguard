"""Read zizmor SARIF and trusted producer counts without invoking an analyzer."""

import json
import stat
from pathlib import Path

import typer

_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


def _finding(result: dict) -> dict:
    rule = result["ruleId"]
    message = result["message"]["text"]
    if not isinstance(rule, str) or not rule or not isinstance(message, str):
        raise ValueError("invalid rule or message")
    locations = []
    for location in result.get("locations", []):
        physical = location.get("physicalLocation", {})
        uri = physical.get("artifactLocation", {}).get("uri")
        if uri is None:
            continue
        if not isinstance(uri, str):
            raise ValueError("invalid SARIF artifact URI")
        region = physical.get("region", {})
        position = {}
        for key in ("startLine", "endLine", "startColumn", "endColumn"):
            if key in region:
                if type(region[key]) is not int or region[key] < 1:
                    raise ValueError("invalid SARIF location")
                position[key] = region[key]
        locations.append({"uri": uri, **position})
    return {"rule": rule, "level": result.get("level"), "message": message, "locations": locations}


def summarize_zizmor(
    path: Path,
    *,
    scanned_files: int | None = None,
    exit_code: int | None = None,
    expect_version: str | None = None,
    limit: int = 50,
) -> dict:
    """Counts come from the producer. Result locations omit clean files."""
    if limit < 0 or (scanned_files is not None and scanned_files < 0):
        raise ValueError("counts must be nonnegative")
    report = {"path": str(path), "scanned_files": scanned_files, "exit_code": exit_code}
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            return {**report, "status": "unreadable"}
        with path.open("rb") as artifact:
            contents = artifact.read(_MAX_ARTIFACT_BYTES + 1)
        if len(contents) > _MAX_ARTIFACT_BYTES:
            return {**report, "status": "too_large", "max_bytes": _MAX_ARTIFACT_BYTES}
        sarif = json.loads(contents)
        if sarif["version"] != "2.1.0":
            raise ValueError("expected SARIF 2.1.0")
        runs = sarif["runs"]
        if not isinstance(runs, list) or not runs:
            raise ValueError("missing SARIF run")
        versions = set()
        findings = []
        issues = []
        count = 0
        for run in runs:
            driver = run["tool"]["driver"]
            if driver["name"] != "zizmor":
                raise ValueError("unexpected SARIF producer")
            version = driver.get("semanticVersion") or driver["version"]
            if not isinstance(version, str) or not version:
                raise ValueError("missing producer version")
            versions.add(version)
            invocations = run.get("invocations", [])
            if not isinstance(invocations, list) or not invocations:
                issues.append("missing invocation status")
            for invocation in invocations:
                if invocation.get("executionSuccessful") is not True:
                    issues.append("analyzer invocation incomplete")
                for field, category in (
                    ("toolExecutionNotifications", "execution"),
                    ("toolConfigurationNotifications", "configuration"),
                ):
                    if any(
                        note.get("level", "warning") in ("warning", "error")
                        for note in invocation.get(field, [])
                    ):
                        issues.append(f"analyzer reported {category} warnings or errors")
            results = run["results"]
            if not isinstance(results, list):
                raise ValueError("invalid SARIF results")
            for result in results:
                finding = _finding(result)
                if count < limit:
                    findings.append(finding)
                count += 1
    except FileNotFoundError:
        return {**report, "status": "missing"}
    except OSError:
        return {**report, "status": "unreadable"}
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
        return {**report, "status": "invalid"}
    if len(versions) > 1 or (expect_version is not None and versions != {expect_version}):
        issues.append("producer version mismatch")
    if exit_code is None:
        issues.append("missing analyzer exit code")
    elif exit_code != 0:
        issues.append("analyzer exited unsuccessfully in SARIF mode")
    if scanned_files is None:
        issues.append("missing scanned-file count")
    elif scanned_files == 0:
        issues.append("zero scanned files")
    return {
        **report,
        "status": "partial" if issues else ("findings" if count else "clean"),
        "versions": sorted(versions),
        "issues": sorted(set(issues)),
        "findings_total": count,
        "findings_omitted": count - len(findings),
        "findings": findings,
    }


def zizmor_report(
    path: Path = typer.Argument(..., help="Existing zizmor SARIF 2.1.0 output."),
    scanned_files: int | None = typer.Option(
        None, min=0, help="Trusted producer scanned-file count."
    ),
    exit_code: int | None = typer.Option(None, help="Analyzer process exit status."),
    expect_version: str | None = typer.Option(None, help="Expected zizmor version."),
    limit: int = typer.Option(50, min=0, help="Maximum returned finding details."),
) -> None:
    """Inspect a zizmor artifact. No repository code or analyzer is executed."""
    report = summarize_zizmor(
        path,
        scanned_files=scanned_files,
        exit_code=exit_code,
        expect_version=expect_version,
        limit=limit,
    )
    typer.echo(json.dumps(report, indent=2))
    if report["status"] != "clean":
        raise typer.Exit(2 if report["status"] == "findings" else 3)


if __name__ == "__main__":
    typer.run(zizmor_report)
