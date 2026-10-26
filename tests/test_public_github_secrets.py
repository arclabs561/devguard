"""A public GitHub sweep that scanned nothing must not read as clean."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from devguard import cli, spec
from devguard.sweeps import public_github_secrets as pgs


@pytest.fixture
def github(monkeypatch):
    """Offline GitHub: one discovered repo, token and scanner configurable."""
    state = {"token": "fixture-token", "repos": ["fixture/repo"], "which": "/bin/trufflehog"}
    runs: list[list[str]] = []

    def run(cmd, *args, **kwargs):
        runs.append(cmd)
        return subprocess.CompletedProcess(cmd, state.get("exit", 0), stdout="", stderr="")

    monkeypatch.setattr(pgs, "_get_github_token", lambda: (state["token"], []))
    monkeypatch.setattr(pgs, "_expand_owners", lambda owners, token: (["fixture"], []))
    monkeypatch.setattr(pgs, "_list_public_repos", lambda owner, **kw: (state["repos"], []))
    monkeypatch.setattr(pgs, "_list_public_repos_via_api", lambda owner, **kw: ([], []))
    monkeypatch.setattr("shutil.which", lambda name: state["which"])
    monkeypatch.setattr(pgs.subprocess, "run", run)
    state["runs"] = runs
    return state


def _scan() -> dict:
    report, _ = pgs.scan_public_github_repos(
        owners=["fixture"],
        include_repos=[],
        exclude_repos=[],
        include_forks=False,
        max_repos=10,
    )
    return report


def test_complete_scan_has_no_coverage_errors(github):
    report = _scan()

    assert report["coverage_errors"] == []
    assert report["scope"]["repos_scanned_count"] == 1
    assert len(github["runs"]) == 1


@pytest.mark.parametrize(
    "gap,needle",
    [
        ("token", "Missing GitHub token"),
        ("which", "trufflehog not found"),
        ("repos", "no public repos selected"),
    ],
)
def test_coverage_gap_is_reported_and_nothing_counts_as_scanned(github, gap, needle):
    github[gap] = [] if gap == "repos" else None

    report = _scan()

    assert len(report["coverage_errors"]) == 1
    assert needle in report["coverage_errors"][0]
    assert report["coverage_errors"][0] in report["errors"]
    assert report["scope"]["repos_scanned_count"] == 0
    assert github["runs"] == []


def _invoke(tmp_path: Path, monkeypatch) -> object:
    monkeypatch.chdir(tmp_path)
    settings: dict[str, dict[str, object]] = {
        name: {"enabled": False} for name in spec.SweepSpec.model_fields
    }
    settings["public_github_secrets"] = {
        "enabled": True,
        "owners": ["fixture"],
        "output": str(tmp_path / "report.json"),
    }
    source = tmp_path / "spec.yaml"
    source.write_text(json.dumps({"name": "fixture", "sweeps": settings}))
    return CliRunner().invoke(cli.app, ["sweep", "--spec", str(source)])


@pytest.mark.parametrize("gap", ["token", "which", "repos"])
def test_cli_exits_3_on_coverage_gap_without_fail_on_errors(github, tmp_path, monkeypatch, gap):
    github[gap] = [] if gap == "repos" else None

    result = _invoke(tmp_path, monkeypatch)

    assert result.exit_code == 3, result.output
    assert "Incomplete coverage" in result.output


def test_cli_per_repo_error_keeps_fail_on_errors_policy(github, tmp_path, monkeypatch):
    github["exit"] = 1

    result = _invoke(tmp_path, monkeypatch)

    report = json.loads((tmp_path / "report.json").read_text())
    assert report["errors"] and report["coverage_errors"] == []
    assert result.exit_code == 0, result.output
