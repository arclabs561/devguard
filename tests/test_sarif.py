"""SARIF conversion keeps findings from every default-on sweep report shape."""

from __future__ import annotations

import json
from pathlib import Path

from devguard.sarif import reports_to_sarif
from devguard.sweeps.credential_file_audit import audit_credential_files
from devguard.sweeps.mcp_security_audit import audit_mcp_security


def _results(sweep: str, report: dict) -> list[dict]:
    return reports_to_sarif([(sweep, report)])["runs"][0]["results"]


def test_credential_file_audit_findings_reach_sarif(tmp_path: Path) -> None:
    netrc = tmp_path / ".netrc"
    netrc.write_text("machine example.invalid login fixture password fixture-password\n")
    netrc.chmod(0o600)
    report, _ = audit_credential_files(home_dir=tmp_path)
    assert report["summary"]["issues_total"] >= 1

    results = _results("credential_file_audit", report)

    assert [r["ruleId"] for r in results] == ["plaintext_netrc_password"]
    assert results[0]["level"] == "error"
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == str(netrc)


def test_mcp_security_audit_findings_reach_sarif(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fixture": {
                        "command": "npx",
                        "env": {"GITHUB_TOKEN": "ghp_abcdef1234567890abcdef1234567890abcd"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    report, _ = audit_mcp_security(dev_root=tmp_path, check_user_configs=False)
    expected = {f["check_id"] for f in report["findings"]}
    assert "mcp_hardcoded_secret" in expected

    results = _results("mcp_security_audit", report)

    assert {r["ruleId"] for r in results} == expected
    assert len(results) == len(report["findings"])
