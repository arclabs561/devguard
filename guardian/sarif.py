"""Convert guardian sweep reports to SARIF 2.1.0 format."""

from __future__ import annotations

from typing import Any

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)

# Map severity strings used across sweeps to SARIF levels.
_SEVERITY_TO_LEVEL: dict[str, str] = {
    "error": "error",
    "critical": "error",
    "high": "error",
    "warning": "warning",
    "medium": "warning",
    "info": "note",
    "note": "note",
    "low": "note",
}


def _sarif_level(severity: str) -> str:
    return _SEVERITY_TO_LEVEL.get(severity.lower(), "warning")


# ---------------------------------------------------------------------------
# Per-sweep extractors
# ---------------------------------------------------------------------------
# Each returns a list of (rule_id, level, message, uri | None) tuples.


def _extract_ai_editor_config(report: dict) -> list[tuple[str, str, str, str | None]]:
    results: list[tuple[str, str, str, str | None]] = []
    for repo in report.get("repos", []):
        repo_path = repo.get("repo_path") or repo.get("repo_name")
        for f in repo.get("findings", []):
            results.append(
                (
                    f.get("check", "unknown"),
                    _sarif_level(f.get("severity", "warning")),
                    f.get("message", ""),
                    repo_path,
                )
            )
    return results


def _extract_cargo_publish(report: dict) -> list[tuple[str, str, str, str | None]]:
    # Same shape as ai_editor_config: repos[].findings[].{check, severity, message}
    return _extract_ai_editor_config(report)


def _extract_gitignore_audit(report: dict) -> list[tuple[str, str, str, str | None]]:
    results: list[tuple[str, str, str, str | None]] = []
    for repo in report.get("repos", []):
        repo_path = repo.get("repo_path")
        is_public = repo.get("is_public", False)
        level = "error" if is_public else "warning"
        if not repo.get("has_gitignore"):
            results.append(
                (
                    "missing_gitignore",
                    level,
                    "Repository has no .gitignore file",
                    repo_path,
                )
            )
        for pattern in repo.get("missing_patterns", []):
            results.append(
                (
                    "missing_gitignore_pattern",
                    level,
                    f"Missing gitignore pattern: {pattern}",
                    repo_path,
                )
            )
        for warn in repo.get("case_warnings", []):
            results.append(
                (
                    "gitignore_case_warning",
                    "note",
                    warn if isinstance(warn, str) else str(warn),
                    repo_path,
                )
            )
    return results


def _extract_dependency_audit(report: dict) -> list[tuple[str, str, str, str | None]]:
    results: list[tuple[str, str, str, str | None]] = []
    for repo in report.get("repos", []):
        repo_path = repo.get("repo_path")
        for v in repo.get("vulns", []):
            sev = v.get("severity", "unknown")
            pkg = v.get("package", "?")
            title = v.get("title", "")
            vid = v.get("id", "unknown")
            msg = f"{vid}: {pkg} - {title}" if title else f"{vid}: {pkg}"
            results.append(
                (
                    f"dependency_vuln_{sev}",
                    _sarif_level(sev),
                    msg,
                    repo_path,
                )
            )
    return results


def _extract_ssh_key_audit(report: dict) -> list[tuple[str, str, str, str | None]]:
    results: list[tuple[str, str, str, str | None]] = []
    for key in report.get("keys", []):
        key_file = key.get("file")
        for issue in key.get("issues", []):
            results.append(
                (
                    "ssh_key_issue",
                    "warning",
                    issue,
                    key_file,
                )
            )
    return results


def _extract_public_github_secrets(report: dict) -> list[tuple[str, str, str, str | None]]:
    results: list[tuple[str, str, str, str | None]] = []
    for f in report.get("findings", []):
        detector = f.get("type", "unknown")
        repo = f.get("repo", "")
        file_path = f.get("file")
        verified = f.get("verified")
        level = "error" if verified else "warning"
        msg = f"Secret detected: {detector} in {repo}"
        if file_path:
            msg += f" ({file_path})"
        uri = file_path if file_path else repo
        results.append(
            (
                f"secret_{detector}",
                level,
                msg,
                uri,
            )
        )
    return results


def _extract_local_dirty_worktree_secrets(report: dict) -> list[tuple[str, str, str, str | None]]:
    # Same top-level findings[] shape as public_github_secrets
    return _extract_public_github_secrets(report)


def _extract_local_dev(report: dict) -> list[tuple[str, str, str, str | None]]:
    results: list[tuple[str, str, str, str | None]] = []
    for hit in report.get("hits", []):
        reason = hit.get("reason", "flagged file")
        file_path = hit.get("file_path")
        repo_path = hit.get("repo_path")
        uri = file_path or repo_path
        results.append(
            (
                "local_dev_hit",
                "warning",
                reason,
                uri,
            )
        )
    return results


def _extract_project_flaudit(report: dict) -> list[tuple[str, str, str, str | None]]:
    results: list[tuple[str, str, str, str | None]] = []
    for repo in report.get("repos", report.get("results", [])):
        repo_path = repo.get("repo_path") or repo.get("repo_name", "")
        for f in repo.get("findings", []):
            # project_flaudit findings may have check/severity/message or
            # category/severity/description
            check = f.get("check") or f.get("category", "unknown")
            sev = f.get("severity", "warning")
            msg = f.get("message") or f.get("description", "")
            results.append(
                (
                    check,
                    _sarif_level(sev),
                    msg,
                    repo_path,
                )
            )
    return results


_EXTRACTORS: dict[str, Any] = {
    "ai_editor_config_audit": _extract_ai_editor_config,
    "cargo_publish_audit": _extract_cargo_publish,
    "gitignore_audit": _extract_gitignore_audit,
    "dependency_audit": _extract_dependency_audit,
    "ssh_key_audit": _extract_ssh_key_audit,
    "public_github_secrets": _extract_public_github_secrets,
    "local_dirty_worktree_secrets": _extract_local_dirty_worktree_secrets,
    "local_dev": _extract_local_dev,
    "project_flaudit": _extract_project_flaudit,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def report_to_sarif(
    report: dict,
    sweep_name: str,
    tool_version: str = "0.1.0",
) -> dict:
    """Convert a guardian sweep report to SARIF 2.1.0 format."""
    extractor = _EXTRACTORS.get(sweep_name)
    if extractor is None:
        # Fallback: try the ai_editor_config shape (repos[].findings[])
        extractor = _extract_ai_editor_config

    raw_results = extractor(report)

    # Collect unique rule IDs
    rule_ids: dict[str, int] = {}
    rules: list[dict] = []
    for rule_id, _level, _msg, _uri in raw_results:
        if rule_id not in rule_ids:
            rule_ids[rule_id] = len(rules)
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {"text": rule_id.replace("_", " ")},
                }
            )

    sarif_results: list[dict] = []
    for rule_id, level, message, uri in raw_results:
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_ids[rule_id],
            "level": level,
            "message": {"text": message},
        }
        if uri:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                    },
                }
            ]
        sarif_results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "guardian",
                        "version": tool_version,
                        "informationUri": "https://github.com/arclabs561/guardian",
                        "rules": rules,
                    },
                },
                "results": sarif_results,
            }
        ],
    }


def reports_to_sarif(
    sweep_reports: list[tuple[str, dict]],
    tool_version: str = "0.1.0",
) -> dict:
    """Convert multiple sweep reports into a single SARIF document.

    Each entry in sweep_reports is (sweep_name, report_dict).
    Each sweep becomes a separate run in the SARIF output.
    """
    runs: list[dict] = []
    for sweep_name, report in sweep_reports:
        single = report_to_sarif(report, sweep_name, tool_version=tool_version)
        runs.extend(single["runs"])

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": runs,
    }
