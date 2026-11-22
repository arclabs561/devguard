import json

import pytest
from typer import Typer
from typer.testing import CliRunner

from devguard.zizmor_report import summarize_zizmor, zizmor_report


@pytest.fixture
def run():
    return {
        "tool": {"driver": {"name": "zizmor", "semanticVersion": "1.33.0"}},
        "invocations": [{"executionSuccessful": True}],
        "results": [
            {
                "ruleId": "zizmor/test",
                "level": "note",
                "message": {"text": "review"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "a.yml"},
                            "region": {"startLine": 10},
                        }
                    }
                ],
            },
        ],
    }


def test_zero_exit_with_findings_and_truncation(tmp_path, run):
    path = tmp_path / "report"
    run["results"] *= 2
    path.write_text(json.dumps({"version": "2.1.0", "runs": [run]}))
    app = Typer()
    app.command()(zizmor_report)
    result = CliRunner().invoke(
        app, [str(path), "--exit-code", "0", "--scanned-files", "3", "--limit", "1"]
    )
    assert result.exit_code == 2
    report = json.loads(result.output)
    assert report["findings_total"] == 2 and report["findings_omitted"] == 1
    assert report["findings"][0]["locations"] == [{"uri": "a.yml", "startLine": 10}]


@pytest.mark.parametrize(
    ("files", "code", "version", "invoked", "status"),
    [
        (2, 0, "1.33.0", True, "clean"),
        (0, 0, None, True, "partial"),
        (None, 0, None, True, "partial"),
        (1, 1, None, True, "partial"),
        (1, None, None, True, "partial"),
        (1, 0, None, False, "partial"),
        (2, 0, "other", True, "partial"),
    ],
)
def test_clean_requires_complete_coverage(tmp_path, run, files, code, version, invoked, status):
    path = tmp_path / "report"
    run["results"] = []
    run["invocations"][0]["executionSuccessful"] = invoked
    path.write_text(json.dumps({"version": "2.1.0", "runs": [run]}))
    assert (
        summarize_zizmor(path, scanned_files=files, exit_code=code, expect_version=version)[
            "status"
        ]
        == status
    )


def test_missing_malformed_and_other_tool(tmp_path, run):
    path = tmp_path / "report"
    assert summarize_zizmor(path)["status"] == "missing"
    path.write_text("{")
    assert summarize_zizmor(path)["status"] == "invalid"
    run["tool"]["driver"]["name"] = "another tool"
    path.write_text(json.dumps({"version": "2.1.0", "runs": [run]}))
    assert summarize_zizmor(path)["status"] == "invalid"


def test_oversized_artifact_is_explicit(tmp_path, monkeypatch):
    monkeypatch.setattr("devguard.zizmor_report._MAX_ARTIFACT_BYTES", 3)
    path = tmp_path / "large"
    path.write_bytes(b"four")
    report = summarize_zizmor(path)
    assert report["status"] == "too_large" and report["max_bytes"] == 3


@pytest.mark.parametrize("field", ["toolConfigurationNotifications", "toolExecutionNotifications"])
def test_clean_run_never_clears_another_runs_notification(tmp_path, run, field):
    path = tmp_path / "report"
    run["results"] = []
    invocation = {"executionSuccessful": True, field: [{"message": {"text": "Check unavailable"}}]}
    degraded = {**run, "invocations": [invocation]}
    path.write_text(json.dumps({"version": "2.1.0", "runs": [degraded, run]}))
    app = Typer()
    app.command()(zizmor_report)
    result = CliRunner().invoke(app, [str(path), "--scanned-files", "2", "--exit-code", "0"])
    assert result.exit_code == 3
    report = json.loads(result.output)
    assert report["status"] == "partial" and report["findings_total"] == 0
    assert any("warnings or errors" in issue for issue in report["issues"])
