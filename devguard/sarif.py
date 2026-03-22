"""Convert devguard sweep reports to SARIF 2.1.0 format."""

from __future__ import annotations

import hashlib
from typing import Any

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)

_HELP_URI = "https://github.com/arclabs561/devguard"

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

# GitHub Code Scanning numeric security-severity (0.0-10.0).
_SEVERITY_TO_SCORE: dict[str, str] = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "2.0",
    "warning": "2.0",
    "error": "8.0",
    "note": "2.0",
    "info": "2.0",
}


def _sarif_level(severity: str) -> str:
    return _SEVERITY_TO_LEVEL.get(severity.lower(), "warning")


def _security_severity(severity: str) -> str:
    return _SEVERITY_TO_SCORE.get(severity.lower(), "5.5")


# Type alias for extractor results:
# (rule_id, level, message, uri | None, severity)
_Finding = tuple[str, str, str, str | None, str]


# ---------------------------------------------------------------------------
# Per-sweep extractors
# ---------------------------------------------------------------------------
# Each returns a list of (rule_id, level, message, uri | None, severity).


def _extract_ai_editor_config(report: dict) -> list[_Finding]:
    results: list[_Finding] = []
    for repo in report.get("repos", []):
        repo_path = repo.get("repo_path") or repo.get("repo_name")
        for f in repo.get("findings", []):
            sev = f.get("severity", "warning")
            results.append(
                (
                    f.get("check", "unknown"),
                    _sarif_level(sev),
                    f.get("message", ""),
                    repo_path,
                    sev,
                )
            )
    return results


def _extract_cargo_publish(report: dict) -> list[_Finding]:
    # Same shape as ai_editor_config: repos[].findings[].{check, severity, message}
    return _extract_ai_editor_config(report)


def _extract_gitignore_audit(report: dict) -> list[_Finding]:
    results: list[_Finding] = []
    for repo in report.get("repos", []):
        repo_path = repo.get("repo_path")
        is_public = repo.get("is_public", False)
        level = "error" if is_public else "warning"
        sev = "high" if is_public else "medium"
        if not repo.get("has_gitignore"):
            results.append(
                (
                    "missing_gitignore",
                    level,
                    "Repository has no .gitignore file",
                    repo_path,
                    sev,
                )
            )
        for pattern in repo.get("missing_patterns", []):
            results.append(
                (
                    "missing_gitignore_pattern",
                    level,
                    f"Missing gitignore pattern: {pattern}",
                    repo_path,
                    sev,
                )
            )
        for warn in repo.get("case_warnings", []):
            results.append(
                (
                    "gitignore_case_warning",
                    "note",
                    warn if isinstance(warn, str) else str(warn),
                    repo_path,
                    "low",
                )
            )
    return results


def _extract_dependency_audit(report: dict) -> list[_Finding]:
    results: list[_Finding] = []
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
                    sev,
                )
            )
    return results


def _extract_ssh_key_audit(report: dict) -> list[_Finding]:
    results: list[_Finding] = []
    for key in report.get("keys", []):
        key_file = key.get("file")
        for issue in key.get("issues", []):
            results.append(
                (
                    "ssh_key_issue",
                    "warning",
                    issue,
                    key_file,
                    "medium",
                )
            )
    return results


def _extract_public_github_secrets(report: dict) -> list[_Finding]:
    results: list[_Finding] = []
    for f in report.get("findings", []):
        detector = f.get("type", "unknown")
        repo = f.get("repo", "")
        file_path = f.get("file")
        verified = f.get("verified")
        level = "error" if verified else "warning"
        sev = "critical" if verified else "high"
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
                sev,
            )
        )
    return results


def _extract_local_dirty_worktree_secrets(report: dict) -> list[_Finding]:
    # Same top-level findings[] shape as public_github_secrets
    return _extract_public_github_secrets(report)


def _extract_local_dev(report: dict) -> list[_Finding]:
    results: list[_Finding] = []
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
                "medium",
            )
        )
    return results


def _extract_project_flaudit(report: dict) -> list[_Finding]:
    results: list[_Finding] = []
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
                    sev,
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


def _partial_fingerprint(rule_id: str, uri: str, message: str) -> str:
    """Stable fingerprint for deduplication across SARIF runs."""
    data = f"{rule_id}:{uri}:{message}".encode()
    return hashlib.sha256(data).hexdigest()[:16]


def _build_rule(rule_id: str, severity: str, sweep_name: str) -> dict:
    """Build a SARIF rule object with all GitHub Code Scanning fields."""
    short_desc = rule_id.replace("_", " ")
    return {
        "id": rule_id,
        "shortDescription": {"text": short_desc},
        "helpUri": _HELP_URI,
        "help": {
            "text": f"{short_desc}. See {_HELP_URI} for remediation guidance.",
            "markdown": (
                f"**{short_desc}**\n\n"
                f"Review and remediate this finding. "
                f"See [{_HELP_URI}]({_HELP_URI}) for details."
            ),
        },
        "defaultConfiguration": {
            "level": _sarif_level(severity),
        },
        "properties": {
            "security-severity": _security_severity(severity),
            "precision": "high",
            "tags": ["security", sweep_name, severity.lower()],
        },
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def report_to_sarif(
    report: dict,
    sweep_name: str,
    tool_version: str = "0.1.0",
) -> dict:
    """Convert a devguard sweep report to SARIF 2.1.0 format."""
    extractor = _EXTRACTORS.get(sweep_name)
    if extractor is None:
        # Fallback: try the ai_editor_config shape (repos[].findings[])
        extractor = _extract_ai_editor_config

    raw_results = extractor(report)

    # Collect unique rule IDs
    rule_ids: dict[str, int] = {}
    rules: list[dict] = []
    for rule_id, _level, _msg, _uri, severity in raw_results:
        if rule_id not in rule_ids:
            rule_ids[rule_id] = len(rules)
            rules.append(_build_rule(rule_id, severity, sweep_name))

    sarif_results: list[dict] = []
    for rule_id, level, message, uri, _severity in raw_results:
        uri_str = uri or ""
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_ids[rule_id],
            "level": level,
            "message": {"text": message},
            "partialFingerprints": {
                "primaryLocationLineHash": _partial_fingerprint(
                    rule_id, uri_str, message
                ),
            },
        }
        loc: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": uri_str} if uri_str else {},
                "region": {"startLine": 1},
            },
        }
        if uri:
            result["locations"] = [loc]
        else:
            # No URI, but still provide region for annotation rendering
            result["locations"] = [
                {
                    "physicalLocation": {
                        "region": {"startLine": 1},
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
                        "name": "devguard",
                        "version": tool_version,
                        "informationUri": _HELP_URI,
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

    All sweeps are consolidated into a single run so GitHub Code Scanning
    treats them as one tool with unified rules and deduplication.
    """
    all_findings: list[tuple[str, _Finding]] = []  # (sweep_name, finding)
    for sweep_name, report in sweep_reports:
        extractor = _EXTRACTORS.get(sweep_name, _extract_ai_editor_config)
        for finding in extractor(report):
            all_findings.append((sweep_name, finding))

    # Collect unique rule IDs across all sweeps
    rule_ids: dict[str, int] = {}
    rules: list[dict] = []
    for sweep_name, (rule_id, _level, _msg, _uri, severity) in all_findings:
        if rule_id not in rule_ids:
            rule_ids[rule_id] = len(rules)
            rules.append(_build_rule(rule_id, severity, sweep_name))

    sarif_results: list[dict] = []
    for _sweep_name, (rule_id, level, message, uri, _severity) in all_findings:
        uri_str = uri or ""
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_ids[rule_id],
            "level": level,
            "message": {"text": message},
            "partialFingerprints": {
                "primaryLocationLineHash": _partial_fingerprint(
                    rule_id, uri_str, message
                ),
            },
        }
        if uri:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": 1},
                    },
                }
            ]
        else:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "region": {"startLine": 1},
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
                        "name": "devguard",
                        "version": tool_version,
                        "informationUri": _HELP_URI,
                        "rules": rules,
                    },
                },
                "results": sarif_results,
            }
        ],
    }
