"""Credential file audit sweep: detect plaintext secrets and bad permissions in dotfiles.

Machine-scoped sweep that checks well-known credential files (~/.aws/credentials,
~/.npmrc, ~/.netrc, ~/.docker/config.json, ~/.kube/config, ~/.pypirc, ~/.ssh/)
for permission issues and plaintext secrets that should use credential helpers,
env var references, or SSO instead.
"""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from typing import Any

from devguard.sweeps._common import utc_now as _utc_now

# Well-known credential files (relative to home dir) and whether they are dirs.
_CREDENTIAL_FILES: list[tuple[str, bool]] = [
    (".aws/credentials", False),
    (".npmrc", False),
    (".netrc", False),
    (".docker/config.json", False),
    (".kube/config", False),
    (".pypirc", False),
    (".ssh", True),
]


def _check_perms(path: Path, *, is_dir: bool) -> tuple[bool, str]:
    """Check file/dir permissions. Returns (ok, octal_string)."""
    try:
        mode = path.stat().st_mode
        file_perms = stat.S_IMODE(mode)
        octal_str = f"{file_perms:04o}"
        if is_dir:
            ok = file_perms == 0o700
        else:
            ok = file_perms in (0o600, 0o400)
        return ok, octal_str
    except OSError:
        return False, "????"


def _read_text_safe(path: Path, limit: int = 64 * 1024) -> str | None:
    """Read file as text, returning None on error. Caps at *limit* bytes."""
    try:
        raw = path.read_bytes()[:limit]
        return raw.decode("utf-8", errors="replace")
    except (OSError, PermissionError):
        return None


def _check_aws_credentials(path: Path) -> list[dict[str, Any]]:
    """Check ~/.aws/credentials for plaintext secret keys."""
    findings: list[dict[str, Any]] = []
    text = _read_text_safe(path)
    if text is None:
        return findings
    # Look for aws_secret_access_key lines that are not using credential_process or sso
    # If the file has credential_process or sso_start_url, it's likely using a helper.
    uses_helper = bool(
        re.search(r"^\s*credential_process\s*=", text, re.MULTILINE)
        or re.search(r"^\s*sso_start_url\s*=", text, re.MULTILINE)
        or re.search(r"^\s*sso_session\s*=", text, re.MULTILINE)
    )
    if not uses_helper and re.search(
        r"^\s*aws_secret_access_key\s*=\s*\S+", text, re.MULTILINE
    ):
        findings.append({
            "check_id": "plaintext_aws_key",
            "severity": "error",
            "message": "aws_secret_access_key in plaintext (use credential_process or SSO)",
        })
    return findings


def _check_npmrc(path: Path) -> list[dict[str, Any]]:
    """Check ~/.npmrc for plaintext auth tokens."""
    findings: list[dict[str, Any]] = []
    text = _read_text_safe(path)
    if text is None:
        return findings
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        # Match _authToken=<value> where value is NOT an env var reference
        m = re.search(r"_authToken\s*=\s*(.+)", stripped)
        if m:
            value = m.group(1).strip()
            # ${NPM_TOKEN} or ${...} patterns are fine
            if not re.fullmatch(r"\$\{[^}]+\}", value):
                findings.append({
                    "check_id": "plaintext_npm_token",
                    "severity": "error",
                    "message": "_authToken contains a literal token (use ${NPM_TOKEN} env var reference)",
                })
                break  # one finding is enough
    return findings


def _check_netrc(path: Path) -> list[dict[str, Any]]:
    """Check ~/.netrc for password entries."""
    findings: list[dict[str, Any]] = []
    text = _read_text_safe(path)
    if text is None:
        return findings
    if re.search(r"\bpassword\s+\S+", text):
        findings.append({
            "check_id": "plaintext_netrc_password",
            "severity": "error",
            "message": "~/.netrc contains plaintext password entries",
        })
    return findings


def _check_docker_config(path: Path) -> list[dict[str, Any]]:
    """Check ~/.docker/config.json for inline auth instead of credsStore."""
    findings: list[dict[str, Any]] = []
    text = _read_text_safe(path)
    if text is None:
        return findings
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return findings
    has_creds_store = bool(data.get("credsStore"))
    auths = data.get("auths", {})
    if not has_creds_store and any("auth" in v for v in auths.values() if isinstance(v, dict)):
        findings.append({
            "check_id": "plaintext_docker_auth",
            "severity": "warning",
            "message": "docker config has inline \"auth\" values instead of credsStore",
        })
    return findings


def _check_kube_config(path: Path) -> list[dict[str, Any]]:
    """Check ~/.kube/config for inline tokens or certificate data."""
    findings: list[dict[str, Any]] = []
    text = _read_text_safe(path)
    if text is None:
        return findings
    if re.search(r"^\s+token:\s+\S+", text, re.MULTILINE) or re.search(
        r"^\s+client-certificate-data:\s+\S+", text, re.MULTILINE
    ):
        findings.append({
            "check_id": "kube_plaintext_token",
            "severity": "warning",
            "message": "kube config contains inline token or client-certificate-data",
        })
    return findings


def _check_pypirc(path: Path) -> list[dict[str, Any]]:
    """Check ~/.pypirc for plaintext passwords."""
    findings: list[dict[str, Any]] = []
    text = _read_text_safe(path)
    if text is None:
        return findings
    if re.search(r"^\s*password\s*=\s*\S+", text, re.MULTILINE):
        findings.append({
            "check_id": "pypirc_plaintext",
            "severity": "error",
            "message": "~/.pypirc contains plaintext password (use OIDC trusted publishing)",
        })
    return findings


# Map relative paths to their content checkers.
_CONTENT_CHECKERS: dict[str, Any] = {
    ".aws/credentials": _check_aws_credentials,
    ".npmrc": _check_npmrc,
    ".netrc": _check_netrc,
    ".docker/config.json": _check_docker_config,
    ".kube/config": _check_kube_config,
    ".pypirc": _check_pypirc,
}


def audit_credential_files(
    *,
    home_dir: Path | None = None,
    extra_paths: list[str] | None = None,
    skip_missing: bool = True,
) -> tuple[dict[str, Any], list[str]]:
    """Audit credential files and return (report, errors)."""
    errors: list[str] = []
    home = home_dir if home_dir is not None else Path.home()

    # Build list of (absolute_path, relative_key, is_dir)
    targets: list[tuple[Path, str, bool]] = []
    for rel, is_dir in _CREDENTIAL_FILES:
        targets.append((home / rel, rel, is_dir))
    for extra in extra_paths or []:
        p = Path(extra).expanduser()
        targets.append((p, str(p), p.is_dir()))

    file_results: list[dict[str, Any]] = []
    total_issues = 0

    for abs_path, rel_key, is_dir in targets:
        if is_dir:
            if not abs_path.is_dir():
                if not skip_missing:
                    errors.append(f"directory not found: {abs_path}")
                continue
        else:
            if not abs_path.exists():
                if not skip_missing:
                    errors.append(f"file not found: {abs_path}")
                continue

        findings: list[dict[str, Any]] = []

        # Permission check
        perms_ok, perms_octal = _check_perms(abs_path, is_dir=is_dir)
        if not perms_ok:
            expected = "0700" if is_dir else "0600 or 0400"
            check_id = "ssh_dir_perms" if rel_key == ".ssh" else "perms_too_open"
            findings.append({
                "check_id": check_id,
                "severity": "error",
                "message": f"permissions {perms_octal} (expected {expected})",
            })

        # Content checks (files only)
        if not is_dir:
            checker = _CONTENT_CHECKERS.get(rel_key)
            if checker:
                findings.extend(checker(abs_path))

        total_issues += len(findings)
        file_results.append({
            "path": str(abs_path),
            "rel_key": rel_key,
            "is_dir": is_dir,
            "exists": True,
            "permissions": perms_octal if (abs_path.exists() or abs_path.is_dir()) else None,
            "permissions_ok": perms_ok,
            "findings": findings,
        })

    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {
            "home_dir": str(home),
            "files_checked": len(file_results),
            "extra_paths": extra_paths or [],
        },
        "summary": {
            "files_checked": len(file_results),
            "issues_total": total_issues,
            "errors_count": sum(
                1 for f in file_results
                for finding in f["findings"]
                if finding["severity"] == "error"
            ),
            "warnings_count": sum(
                1 for f in file_results
                for finding in f["findings"]
                if finding["severity"] == "warning"
            ),
        },
        "files": file_results,
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
