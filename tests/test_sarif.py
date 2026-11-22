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


def test_workflow_finding_points_to_workflow_in_checkout():
    path = ".github/workflows/release.yml"
    report = {
        "repos": [
            {
                "repo_path": "/some/runner/checkout",
                "findings": [
                    {
                        "check": "event_selected_checkout",
                        "severity": "error",
                        "file": path,
                        "message": "checkout",
                    }
                ],
            }
        ]
    }
    [result] = _results("publish_workflow_audit", report)
    assert result["ruleId"] == "event_selected_checkout"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == path


def test_workflow_jobs_keep_identity_when_the_source_line_moves(tmp_path):
    from devguard.finding_evidence import add_repo_finding_ids
    from devguard.fleet import extract_findings
    from devguard.sweeps.publish_workflow_audit import audit_workflows

    workflow = tmp_path / ".github/workflows/test.yml"
    workflow.parent.mkdir(parents=True)
    body = (
        "on: pull_request\n"
        "permissions: {id-token: write}\n"
        "jobs:\n"
        '  "first": {steps: [{run: "echo first"}]}\n'
        '  second: {steps: [{run: "echo second"}]}\n'
    )

    def check(text):
        workflow.write_text(text)
        findings = audit_workflows(tmp_path)
        report = {"repos": [{"repo_path": str(tmp_path), "findings": findings}]}
        results = _results("publish_workflow_audit", report)
        ids = [r["partialFingerprints"]["devguard/v1"] for r in results]
        add_repo_finding_ids("publish_workflow_audit", report)
        assert [f["finding_id"] for f in findings] == ids
        normalized = extract_findings({"publish_workflow_audit": report})
        assert [f["finding_id"] for f in normalized] == ids
        assert len(set(ids)) == 2
        points = [r["locations"][0]["physicalLocation"] for r in results]
        assert all(p["artifactLocation"]["uri"] == ".github/workflows/test.yml" for p in points)
        return ids, [p["region"]["startLine"] for p in points]

    ids, lines = check(body)
    assert lines == [4, 5]
    shifted, lines = check("# one\n# two\n# three\n" + body)
    assert shifted == ids
    assert lines == [7, 8]


def test_count_and_explicit_links_across_outputs(tmp_path, monkeypatch):
    from io import StringIO

    from rich.console import Console

    from devguard import __version__, cli
    from devguard.fleet import extract_findings
    from devguard.sarif import report_to_sarif

    sweep = "repo_hygiene"
    raw = {
        "check": "stale_gitkeep",
        "severity": "low",
        "files": ["docs/.gitkeep", "data files/.gitkeep"],
        "message": "101 stale files",
        "source_url": "https://example.org/issue/2",
        "evidence_url": "https://example.org/fixture",
    }
    report = {"repos": [{"repo_path": str(tmp_path), "findings": [raw]}]}

    def render():
        sarif = report_to_sarif(report, sweep)
        assert sarif == reports_to_sarif([(sweep, report)])
        assert sarif["runs"][0]["tool"]["driver"]["version"] == __version__
        result = sarif["runs"][0]["results"][0]
        [item] = extract_findings({sweep: report})
        assert result["partialFingerprints"]["devguard/v1"] == item["finding_id"]
        assert result["locations"][0]["physicalLocation"] == {
            "artifactLocation": {"uri": "docs/.gitkeep"}
        }
        assert (
            result["relatedLocations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            == "data%20files/.gitkeep"
        )
        display = StringIO()
        monkeypatch.setattr(cli, "console", Console(file=display, width=80))
        cli._print_repo_hygiene_table(report)
        for key in ("source_url", "evidence_url"):
            assert item[key] == raw[key] == result["properties"][key]
            assert raw[key] in display.getvalue()
        assert raw["message"] in result["message"]["text"]
        return item["finding_id"]

    identity = render()
    raw["message"] = "102 stale files"
    assert render() == identity
    del raw["source_url"]
    raw["evidence_url"] = "file:///private"
    assert "properties" not in _results(sweep, report)[0]


def test_docs_finding_tracks_matching_structured_position():
    def result(line, wording):
        finding = {
            "file": "README.md",
            "line": line,
            "check": "docs_quality:vale/Voice",
            "message": f"README.md:{line}: {wording}",
        }
        return _results("docs_quality", {"repos": [{"findings": [finding]}]})[0]

    original = result(5, "Prefer active voice.")
    moved = result(8, "Prefer active voice.")
    assert original["partialFingerprints"] == moved["partialFingerprints"]
    assert moved["locations"][0]["physicalLocation"]["region"] == {"startLine": 8}
    assert result(8, "Different text.")["partialFingerprints"] != moved["partialFingerprints"]


def test_secret_alerts_keep_their_own_score_in_either_order_and_alone():
    def scores(rows):
        run = reports_to_sarif([("public_github_secrets", {"findings": rows})])["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        by_file = {}
        for result in run["results"]:
            rule = rules[result["ruleIndex"]]
            assert result["ruleId"] == rule["id"]
            file = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            by_file[file] = (
                rule["id"],
                rule["properties"]["security-severity"],
                result["level"],
                result["partialFingerprints"],
            )
        return rules, by_file

    a = {"type": "fixture", "repo": "example/project", "file": "a.txt", "verified": False}
    b = {**a, "file": "b.txt", "verified": True}
    rules, combined = scores([a, b])
    assert (rules, combined) == scores([b, a])
    assert combined == scores([a])[1] | scores([b])[1]
    assert combined["a.txt"][1:3] == ("8.0", "warning")
    assert combined["b.txt"][1:3] == ("9.5", "error")


def test_mixed_generic_rules_preserve_distinct_severities_and_literal_ids():
    sweep = "sample"
    names = ["quality", "quality", "quality@sample/high"]
    findings = [
        {"check": n, "severity": s} for n, s in zip(names, ["low", "high", "low"], strict=True)
    ]
    run = reports_to_sarif([(sweep, {"repos": [{"findings": findings}]})])["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len({rule["id"] for rule in rules}) == 3
    assert run["results"][-1]["ruleId"] == names[-1]
    assert [rules[r["ruleIndex"]]["properties"]["security-severity"] for r in run["results"]] == [
        "2.0",
        "8.0",
        "2.0",
    ]
