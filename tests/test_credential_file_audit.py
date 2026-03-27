"""Tests for credential file audit sweep."""

from __future__ import annotations

import json
from pathlib import Path

from devguard.sweeps.credential_file_audit import audit_credential_files

# ---------------------------------------------------------------------------
# AWS credentials
# ---------------------------------------------------------------------------


def test_aws_credentials_plaintext(tmp_path: Path) -> None:
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    creds = aws_dir / "credentials"
    creds.write_text(
        "[default]\n"
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )
    creds.chmod(0o600)

    report, errors = audit_credential_files(home_dir=tmp_path)
    findings = _findings_for(report, ".aws/credentials")
    assert any(f["check_id"] == "plaintext_aws_key" for f in findings)


def test_aws_credentials_sso(tmp_path: Path) -> None:
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    creds = aws_dir / "credentials"
    creds.write_text(
        "[default]\n"
        "sso_start_url = https://my-sso-portal.awsapps.com/start\n"
        "sso_account_id = 123456789012\n"
    )
    creds.chmod(0o600)

    report, errors = audit_credential_files(home_dir=tmp_path)
    findings = _findings_for(report, ".aws/credentials")
    assert not any(f["check_id"] == "plaintext_aws_key" for f in findings)


# ---------------------------------------------------------------------------
# .npmrc
# ---------------------------------------------------------------------------


def test_npmrc_plaintext_token(tmp_path: Path) -> None:
    npmrc = tmp_path / ".npmrc"
    npmrc.write_text("//registry.npmjs.org/:_authToken=npm_abc123\n")
    npmrc.chmod(0o600)

    report, _ = audit_credential_files(home_dir=tmp_path)
    findings = _findings_for(report, ".npmrc")
    assert any(f["check_id"] == "plaintext_npm_token" for f in findings)


def test_npmrc_env_ref(tmp_path: Path) -> None:
    npmrc = tmp_path / ".npmrc"
    npmrc.write_text("//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n")
    npmrc.chmod(0o600)

    report, _ = audit_credential_files(home_dir=tmp_path)
    findings = _findings_for(report, ".npmrc")
    assert not any(f["check_id"] == "plaintext_npm_token" for f in findings)


# ---------------------------------------------------------------------------
# Docker config
# ---------------------------------------------------------------------------


def test_docker_config_auth(tmp_path: Path) -> None:
    docker_dir = tmp_path / ".docker"
    docker_dir.mkdir()
    cfg = docker_dir / "config.json"
    cfg.write_text(
        json.dumps(
            {
                "auths": {"https://index.docker.io/v1/": {"auth": "dXNlcjpwYXNz"}},
            }
        )
    )
    cfg.chmod(0o600)

    report, _ = audit_credential_files(home_dir=tmp_path)
    findings = _findings_for(report, ".docker/config.json")
    assert any(f["check_id"] == "plaintext_docker_auth" for f in findings)


def test_docker_config_credstore(tmp_path: Path) -> None:
    docker_dir = tmp_path / ".docker"
    docker_dir.mkdir()
    cfg = docker_dir / "config.json"
    cfg.write_text(json.dumps({"credsStore": "desktop"}))
    cfg.chmod(0o600)

    report, _ = audit_credential_files(home_dir=tmp_path)
    findings = _findings_for(report, ".docker/config.json")
    assert not any(f["check_id"] == "plaintext_docker_auth" for f in findings)


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


def test_permissions_too_open(tmp_path: Path) -> None:
    npmrc = tmp_path / ".npmrc"
    npmrc.write_text("# empty\n")
    npmrc.chmod(0o644)

    report, _ = audit_credential_files(home_dir=tmp_path)
    findings = _findings_for(report, ".npmrc")
    assert any(f["check_id"] == "perms_too_open" for f in findings)


def test_permissions_correct(tmp_path: Path) -> None:
    npmrc = tmp_path / ".npmrc"
    npmrc.write_text("# empty\n")
    npmrc.chmod(0o600)

    report, _ = audit_credential_files(home_dir=tmp_path)
    findings = _findings_for(report, ".npmrc")
    assert not any(f["check_id"] == "perms_too_open" for f in findings)


# ---------------------------------------------------------------------------
# .netrc
# ---------------------------------------------------------------------------


def test_netrc_password(tmp_path: Path) -> None:
    netrc = tmp_path / ".netrc"
    netrc.write_text("machine github.com\nlogin user\npassword secret\n")
    netrc.chmod(0o600)

    report, _ = audit_credential_files(home_dir=tmp_path)
    findings = _findings_for(report, ".netrc")
    assert any(f["check_id"] == "plaintext_netrc_password" for f in findings)


# ---------------------------------------------------------------------------
# .pypirc
# ---------------------------------------------------------------------------


def test_pypirc_password(tmp_path: Path) -> None:
    pypirc = tmp_path / ".pypirc"
    pypirc.write_text("[pypi]\nusername = __token__\npassword = pypi-secret\n")
    pypirc.chmod(0o600)

    report, _ = audit_credential_files(home_dir=tmp_path)
    findings = _findings_for(report, ".pypirc")
    assert any(f["check_id"] == "pypirc_plaintext" for f in findings)


# ---------------------------------------------------------------------------
# .kube/config
# ---------------------------------------------------------------------------


def test_kube_plaintext_token(tmp_path: Path) -> None:
    kube_dir = tmp_path / ".kube"
    kube_dir.mkdir()
    cfg = kube_dir / "config"
    cfg.write_text(
        "apiVersion: v1\n"
        "users:\n"
        "- name: admin\n"
        "  user:\n"
        "    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9\n"
    )
    cfg.chmod(0o600)

    report, _ = audit_credential_files(home_dir=tmp_path)
    findings = _findings_for(report, ".kube/config")
    assert any(f["check_id"] == "kube_plaintext_token" for f in findings)


# ---------------------------------------------------------------------------
# skip_missing
# ---------------------------------------------------------------------------


def test_skip_missing(tmp_path: Path) -> None:
    """skip_missing=True suppresses findings for nonexistent files."""
    report, errors = audit_credential_files(home_dir=tmp_path, skip_missing=True)
    # No files exist, so no file results and no errors
    assert report["summary"]["issues_total"] == 0
    assert errors == []


# ---------------------------------------------------------------------------
# Report structure
# ---------------------------------------------------------------------------


def test_report_structure(tmp_path: Path) -> None:
    report, _ = audit_credential_files(home_dir=tmp_path)
    assert "generated_at" in report
    assert "scope" in report
    assert "summary" in report
    assert "files" in report
    assert "home_dir" in report["scope"]
    assert "files_checked" in report["summary"]
    assert "issues_total" in report["summary"]
    assert "errors_count" in report["summary"]
    assert "warnings_count" in report["summary"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _findings_for(report: dict, rel_key: str) -> list[dict]:
    """Extract findings list for a given rel_key from the report."""
    for entry in report["files"]:
        if entry["rel_key"] == rel_key:
            return entry["findings"]
    return []
