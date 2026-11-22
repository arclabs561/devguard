"""Shared source locations and traceable identifiers for structured findings."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


def locations(finding: dict, repo_path: str = "") -> list[tuple[str, int | None]]:
    """Keep source order. Some legacy producers store path:line in files[]."""
    primary = finding.get("file") or finding.get("file_path") or finding.get("path")
    files = finding.get("files")
    candidates = [primary, *(files if isinstance(files, list) else [])]
    result: list[tuple[str, int | None]] = []
    seen = set()
    for value in candidates:
        if not isinstance(value, str) or not value:
            continue
        line = finding.get("line") if value == primary else None
        path, sep, suffix = value.rpartition(":")
        if sep and path and len(suffix) <= 10 and suffix.isascii() and suffix.isdecimal():
            value = path
            if line is None:
                line = int(suffix)
        if repo_path and Path(value).is_absolute():
            try:
                value = Path(value).relative_to(repo_path).as_posix()
            except ValueError:
                pass
        point = (value, line if type(line) is int and line > 0 else None)
        if point not in seen:
            seen.add(point)
            result.append(point)
    return result


def references(finding: dict) -> dict[str, str]:
    """Only pass explicit, usable links to readers; never infer them from prose."""
    result = {}
    for key in ("source_url", "evidence_url"):
        value = finding.get(key)
        if isinstance(value, str) and not any(c.isspace() or ord(c) < 32 for c in value):
            try:
                url = urlsplit(value)
                if (
                    url.scheme in {"http", "https"}
                    and url.hostname
                    and not url.username
                    and not url.password
                ):
                    result[key] = value
            except ValueError:
                continue
    return result


def finding_id(sweep: str, rule: str, path: str, finding: dict[str, Any]) -> str:
    """Location within a report, with source lines and observed counts excluded."""
    subject = finding.get("subject") or finding.get("job")
    step = finding.get("step_id") or finding.get("step")
    # Old reports can contain distinct unkeyed diagnostics at the same path.
    # Keep their discriminator unless the producer supplies a semantic subject.
    if subject is None and not isinstance(finding.get("files"), list) and "count" not in finding:
        subject = finding.get("message") or finding.get("detail") or finding.get("reason")
        # Documentation tools can repeat their structured position in the message.
        line = finding.get("line")
        if isinstance(subject, str) and type(line) is int and line > 0:
            subject = subject.removeprefix(f"{finding.get('file') or path}:{line}: ")
    key = json.dumps([sweep, rule, path, subject, step], ensure_ascii=True)
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def add_repo_finding_ids(sweep: str, report: dict) -> None:
    """Add comparison keys without replacing the original JSON report evidence."""
    for repo in report.get("repos", []):
        if not isinstance(repo, dict):
            continue
        for finding in repo.get("findings", []):
            if isinstance(finding, dict) and isinstance(finding.get("check"), str):
                points = locations(finding, repo.get("repo_path") or "")
                path = points[0][0] if points else ""
                finding["finding_id"] = finding_id(sweep, finding["check"], path, finding)
