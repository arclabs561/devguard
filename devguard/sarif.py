"""Convert devguard sweep reports to SARIF 2.1.0 format."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from urllib.parse import quote

from devguard import __version__
from devguard.finding_evidence import finding_id, locations, references

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


def _extract_local_history_secrets(report: dict) -> list[_Finding]:
    results: list[_Finding] = []
    for f in report.get("findings", []):
        sev = f.get("severity", "high")
        rule = "history_secret" if not f.get("in_head") else "committed_secret"
        results.append((rule, _sarif_level(sev), f.get("message", ""), f.get("file"), sev))
    return results


def _extract_exec_config_audit(report: dict) -> list[_Finding]:
    return [
        (
            f.get("check_id", "runs_on_open"),
            _sarif_level(f.get("severity", "medium")),
            f.get("message", ""),
            f.get("file"),
            f.get("severity", "medium"),
        )
        for f in report.get("findings", [])
    ]


def _extract_repo_lint(report: dict) -> list[_Finding]:
    return [
        (
            f.get("check", "repo_lint"),
            _sarif_level(f.get("severity", "low")),
            f.get("message", ""),
            f.get("file"),
            f.get("severity", "low"),
        )
        for f in report.get("findings", [])
    ]


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


def _extract_git_identity_audit(report: dict) -> list[_Finding]:
    results: list[_Finding] = []
    for f in report.get("findings", []):
        sev = f.get("severity", "warning")
        source = f.get("source", "git identity")
        email = f.get("email", "")
        repo_path = f.get("repo_path")
        msg = f.get("message") or f"{source}: {email}"
        results.append(
            (
                f.get("check_id", "git_identity_issue"),
                _sarif_level(sev),
                msg,
                repo_path,
                sev,
            )
        )
    return results


def _extract_credential_file_audit(report: dict) -> list[_Finding]:
    results: list[_Finding] = []
    for entry in report.get("files", []):
        for f in entry.get("findings", []):
            sev = f.get("severity", "warning")
            results.append(
                (
                    f.get("check_id", "credential_file_issue"),
                    _sarif_level(sev),
                    f.get("message", ""),
                    entry.get("path"),
                    sev,
                )
            )
    return results


def _extract_mcp_security_audit(report: dict) -> list[_Finding]:
    return [
        (
            f.get("check_id", "mcp_security_issue"),
            _sarif_level(f.get("severity", "warning")),
            f.get("message", ""),
            f.get("file"),
            f.get("severity", "warning"),
        )
        for f in report.get("findings", [])
    ]


_EXTRACTORS: dict[str, Any] = {
    "gitignore_audit": _extract_gitignore_audit,
    "git_identity_audit": _extract_git_identity_audit,
    "dependency_audit": _extract_dependency_audit,
    "ssh_key_audit": _extract_ssh_key_audit,
    "public_github_secrets": _extract_public_github_secrets,
    "local_dirty_worktree_secrets": _extract_local_dirty_worktree_secrets,
    "local_history_secrets": _extract_local_history_secrets,
    "exec_config_audit": _extract_exec_config_audit,
    "repo_lint": _extract_repo_lint,
    "local_dev": _extract_local_dev,
    "project_flaudit": _extract_project_flaudit,
    "credential_file_audit": _extract_credential_file_audit,
    "mcp_security_audit": _extract_mcp_security_audit,
}


def _records(sweep: str, report: dict) -> Iterator[tuple[_Finding, dict]]:
    extractor = _EXTRACTORS.get(sweep)
    if extractor is not None:
        rows = extractor(report)
        # These extractors return one row per raw finding, in the original order.
        direct = sweep in {
            "public_github_secrets",
            "local_dirty_worktree_secrets",
            "local_history_secrets",
            "exec_config_audit",
            "repo_lint",
            "git_identity_audit",
            "mcp_security_audit",
        }
        items = report.get("findings", []) if direct else ()
        for index, row in enumerate(rows):
            _, _, message, uri, _ = row
            evidence = dict(items[index]) if direct else {}
            evidence.update(message=message, file=uri)
            yield row, evidence
        return
    for repo in report.get("repos", []):
        for raw in repo.get("findings", []):
            sev = raw.get("severity", "warning")
            yield (
                (raw.get("check", "unknown"), _sarif_level(sev), raw.get("message", ""), None, sev),
                raw | {"repo_path": repo.get("repo_path") or ""},
            )


def _build_rule(rule_id: str, rule_name: str, severity: str, sweep_name: str) -> dict:
    """Build a SARIF rule object with all GitHub Code Scanning fields."""
    short_desc = rule_name.replace("_", " ")
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


def report_to_sarif(report: dict, sweep_name: str, tool_version: str = __version__) -> dict:
    """Convert one report using the same location and identity rules as a fleet."""
    return reports_to_sarif([(sweep_name, report)], tool_version)


def reports_to_sarif(
    sweep_reports: list[tuple[str, dict]],
    tool_version: str = __version__,
) -> dict:
    """Convert one or more sweep reports into a single SARIF run."""
    # GitHub reads security-severity from the rule descriptor, so findings
    # with different ratings cannot correctly share one descriptor.
    records = [
        (sweep, row, raw) for sweep, report in sweep_reports for row, raw in _records(sweep, report)
    ]
    variants: dict[str, set[tuple[str, str]]] = {}
    for sweep, (rule, _, _, _, severity), _ in records:
        variants.setdefault(rule, set()).add((sweep, severity.lower()))

    used_ids = set(variants)
    descriptors: dict[tuple[str, str, str], tuple[str, int]] = {}
    rules: list[dict] = []
    for rule, groups in sorted(variants.items()):
        for sweep, severity in sorted(groups):
            descriptor_id = rule
            # Verification can vary even between successive single-alert
            # scans. Keep this producer's severity-specific ID in both cases.
            if len(groups) > 1 or sweep in {
                "public_github_secrets",
                "local_dirty_worktree_secrets",
            }:
                descriptor_id = f"{rule}@{quote(sweep, safe='')}/{quote(severity, safe='')}"
                while descriptor_id in used_ids:
                    descriptor_id += "@"
                used_ids.add(descriptor_id)
            descriptors[rule, sweep, severity] = descriptor_id, len(rules)
            rules.append(_build_rule(descriptor_id, rule, severity, sweep))

    sarif_results: list[dict] = []
    for sweep, (rule, level, message, _, severity), raw in records:
        descriptor_id, rule_index = descriptors[rule, sweep, severity.lower()]
        points = locations(raw, raw.get("repo_path", ""))
        primary = points[0][0] if points else ""
        identity = finding_id(sweep, rule, primary, raw)
        result: dict[str, Any] = {
            "ruleId": descriptor_id,
            "ruleIndex": rule_index,
            "level": level,
            "message": {"text": message},
            "partialFingerprints": {"devguard/v1": identity},
        }
        if refs := references(raw):
            result["properties"] = refs
            result["message"]["text"] += "\n" + "\n".join(refs.values())
        for index, (path, line) in enumerate(points):
            physical: dict[str, Any] = {"artifactLocation": {"uri": quote(path, safe="/:")}}
            if line is not None:
                physical["region"] = {"startLine": line}
            if index == 0:
                result["locations"] = [{"physicalLocation": physical}]
            else:
                result.setdefault("relatedLocations", []).append(
                    {"id": index, "physicalLocation": physical}
                )
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
