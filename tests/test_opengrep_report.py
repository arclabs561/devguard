import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from devguard.cli import app
from devguard.opengrep_report import summarize_report


def scan(**overrides):
    return {
        "version": "1.30.2",
        "results": [],
        "errors": [],
        "paths": {"scanned": ["sample.rs"]},
        **overrides,
    }


@pytest.mark.parametrize(
    ("content", "status"),
    [
        ("[]", "invalid"),
        ("{", "invalid"),
        (json.dumps(scan(version=None)), "invalid"),
        ('{"results":[]}', "invalid"),
        (json.dumps(scan(results=[None])), "invalid"),
        (json.dumps(scan(errors=None)), "invalid"),
        (json.dumps(scan(paths={"scanned": []})), "no_targets"),
        (json.dumps(scan(skipped_rules=[{"rule_id": "incomplete"}])), "partial"),
        (json.dumps(scan()), "clean"),
    ],
)
def test_report_coverage(tmp_path, content, status):
    path = tmp_path / "report.json"
    path.write_text(content)
    assert summarize_report(path)["status"] == status


def test_cli_distinguishes_findings_and_incomplete_scans(tmp_path: Path):
    runner = CliRunner()
    path = tmp_path / "report.json"
    finding = {"check_id": "fixture", "extra": {"lines": "do not copy source text"}}

    path.write_text(json.dumps(scan()))
    assert runner.invoke(app, ["opengrep-report", str(path)]).exit_code == 0
    mismatch = runner.invoke(app, ["opengrep-report", str(path), "--expect-version", "1.30.1"])
    assert mismatch.exit_code == 3
    report = json.loads(mismatch.stdout)["reports"][0]
    assert (report["status"], report["version"]) == ("version_mismatch", "1.30.2")
    path.write_text(json.dumps(scan(results=[finding])))
    assert runner.invoke(app, ["opengrep-report", str(path)]).exit_code == 2

    partial = tmp_path / "partial.json"
    partial.write_text(json.dumps(scan(results=[finding], errors=[{"message": "scanner error"}])))
    result = runner.invoke(
        app, ["opengrep-report", str(path), str(partial), str(tmp_path / "missing"), str(tmp_path)]
    )
    assert result.exit_code == 3
    reports = json.loads(result.stdout)["reports"]
    assert [r["status"] for r in reports] == ["findings", "partial", "missing", "unreadable"]
    assert reports[1]["findings"] == reports[1]["errors"] == reports[1]["scanned_files"] == 1
    assert "do not copy source text" not in result.stdout
