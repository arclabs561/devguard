import json
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired

import pytest

from devguard import fleet, review_rank


def row(path, reach, role="source"):
    return {"file": path, "dependents": reach, "role": role}


def write_rows(root, rows):
    for r in rows:
        path = root / r["file"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()


def files(rows):
    return {
        "schema_version": 1,
        "ok": True,
        "command": "files",
        "rows": rows,
        "rows_total": len(rows),
    }


@pytest.mark.parametrize("legacy", [False, True])
def test_exact_matches_and_affected_tests(monkeypatch, tmp_path, legacy):
    rows = [row("pkg/shared.py", 3), row("pkg/leaf.py", 0), row("tests/test_api.py", 0, "test")]
    write_rows(tmp_path, rows)
    impact = {
        "changed": ["pkg/leaf.py", "pkg/shared.py"],
        "affected": ["tests/test_api.py"],
        "affected_count": 1,
    }
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        assert Path(kwargs["cwd"]) != tmp_path
        assert argv[2] == str(tmp_path) and "--include-tests" in argv
        assert kwargs["env"]["GOPROXY"] == "off"
        if "--affected" in argv:
            assert argv[-1] == "pkg/leaf.py,pkg/shared.py"
            report = (
                json.dumps(files([])) + "\n" + json.dumps(impact)
                if legacy
                else json.dumps(files([]) | impact)
            )
        else:
            report = json.dumps(files(rows))
        return CompletedProcess(argv, 0, report, "")

    monkeypatch.setattr(review_rank.shutil, "which", lambda _: "/bin/pkgrank")
    monkeypatch.setattr(review_rank.subprocess, "run", run)
    findings = [
        {"files": ["pkg/shared.py:21:3", str(tmp_path / "pkg/leaf.py"), "pkg/shared.py"]},
        {"file": "other/shared.py:21"},
        {"file": "../pkg/shared.py"},
        {"file": "./pkg/leaf.py"},
    ]
    report = review_rank.rank_findings(tmp_path, findings, 60)
    assert len(calls) == 2
    assert report["matched_findings"] == 2
    assert report["unmatched_files"] == ["other/shared.py"]
    assert report["candidate_tests"] == ["tests/test_api.py"]
    assert findings[0]["pkgrank"] == {
        "file": "pkg/shared.py",
        "dependents": 3,
        "matched_files": ["pkg/leaf.py", "pkg/shared.py"],
    }
    assert findings[-1]["pkgrank"]["dependents"] == 0
    assert all("pkgrank" not in f for f in findings[1:3])


def test_missing_and_partial_graph(monkeypatch, tmp_path):
    findings = [{"file": "example.py"}]
    monkeypatch.setattr(review_rank.shutil, "which", lambda _: None)
    assert review_rank.rank_findings(tmp_path, findings, 30)["status"] == "unavailable"
    monkeypatch.setattr(review_rank.shutil, "which", lambda _: "/bin/pkgrank")
    partial = files([row("example.py", 8)]) | {"rows_total": 9}
    monkeypatch.setattr(review_rank, "_reports", lambda *args: [partial])
    assert review_rank.rank_findings(tmp_path, findings, 30)["status"] == "unavailable"
    assert findings == [{"file": "example.py"}]


def test_leaf_tests_are_their_own_candidates(monkeypatch, tmp_path):
    write_rows(tmp_path, [row("tests/test_leaf.py", 0), row("leaf.py", 0)])

    def reports(_exe, _root, _cwd, args, _deadline):
        assert "--affected" not in args
        return [files([row("tests/test_leaf.py", 0, "test"), row("leaf.py", 0)])]

    monkeypatch.setattr(review_rank.shutil, "which", lambda _: "/bin/pkgrank")
    monkeypatch.setattr(review_rank, "_reports", reports)
    findings = [{"file": "tests/test_leaf.py"}, {"file": "leaf.py"}]
    assert review_rank.rank_findings(tmp_path, findings, 10)["candidate_tests"] == [
        "tests/test_leaf.py"
    ]


def test_failed_test_selection_preserves_file_evidence(monkeypatch, tmp_path):
    write_rows(tmp_path, [row("hot.py", 3)])

    def reports(_exe, _root, _cwd, args, _deadline):
        if "--affected" in args:
            raise TimeoutExpired("pkgrank", 1)
        return [files([row("hot.py", 3)])]

    monkeypatch.setattr(review_rank.shutil, "which", lambda _: "/bin/pkgrank")
    monkeypatch.setattr(review_rank, "_reports", reports)
    findings = [{"file": "hot.py"}]
    result = review_rank.rank_findings(tmp_path, findings, 1)
    assert "tests_unavailable" in result and "candidate_tests" not in result
    assert findings[0]["pkgrank"]["dependents"] == 3


def test_review_order_keeps_severity_and_unknowns():
    def finding(path, sev, reach=None):
        base = {"file": path, "severity": sev, "sweep": "example", "check": "same"}
        return base if reach is None else base | {"pkgrank": {"file": path, "dependents": reach}}

    repo = fleet.RepoResult("repo", None, None, "", "scanned", 2, 0)
    repo.findings = [
        finding("unknown", "medium"),
        finding("leaf", "medium", 0),
        finding("hot", "medium", 20),
        finding("workflow", "high"),
    ]
    assert [r["file"] for r in fleet.review_order([repo])] == ["workflow", "hot", "leaf", "unknown"]


@pytest.mark.parametrize("rows,status", [([], "empty"), ([row("main.py", 0)], "partial")])
def test_uncovered_nested_finding_has_no_test_selection(monkeypatch, tmp_path, rows, status):
    nested = [{"ecosystem": "js", "manifest": "ui/package.json"}]
    write_rows(tmp_path, rows)
    graph = files(rows) | {"unscanned_projects": nested}
    monkeypatch.setattr(review_rank.shutil, "which", lambda _: "/bin/pkgrank")
    monkeypatch.setattr(review_rank, "_reports", lambda *args: [graph])
    findings = [{"file": "ui/app.ts", "severity": "high"}]
    result = review_rank.rank_findings(tmp_path, findings, 10)
    assert result["status"] == status
    assert result["unscanned_projects"] == nested
    assert result["unmatched_files"] == ["ui/app.ts"]
    assert result["matched_findings"] == 0
    assert "tests_unavailable" in result and "candidate_tests" not in result
    assert findings == [{"file": "ui/app.ts", "severity": "high"}]


def test_partial_graph_preserves_verified_test_candidates(monkeypatch, tmp_path):
    nested = [{"ecosystem": "js", "manifest": "web/package.json"}]
    write_rows(tmp_path, [row("tests/test_api.py", 0)])
    graph = files([row("tests/test_api.py", 0, "test")]) | {"unscanned_projects": nested}
    monkeypatch.setattr(review_rank.shutil, "which", lambda _: "/bin/pkgrank")
    monkeypatch.setattr(review_rank, "_reports", lambda *args: [graph])
    result = review_rank.rank_findings(tmp_path, [{"files": ["tests/test_api.py", "web/ui.js"]}], 5)
    assert result["candidate_tests"] == ["tests/test_api.py"]
    assert result["unmatched_files"] == ["web/ui.js"]
    assert result["status"] == "partial"


def test_deleted_tracked_finding_does_not_suggest_a_nonexistent_test(monkeypatch, tmp_path):
    graph = files([row("tests/test_deleted.py", 0, "test")])
    monkeypatch.setattr(review_rank.shutil, "which", lambda _: "/bin/pkgrank")
    monkeypatch.setattr(review_rank, "_reports", lambda *args: [graph])
    findings = [{"file": "tests/test_deleted.py"}]
    result = review_rank.rank_findings(tmp_path, findings, 5)
    assert result["status"] == "unavailable"
    assert result["missing_files"] == ["tests/test_deleted.py"]
    assert "candidate_tests" not in result and "pkgrank" not in findings[0]


def test_test_disappearing_during_affected_query_is_unavailable(monkeypatch, tmp_path):
    rows = [row("module.py", 1), row("test_module.py", 0, "test")]
    write_rows(tmp_path, rows)

    def reports(_exe, _root, _cwd, args, _deadline):
        if "--affected" in args:
            (tmp_path / "test_module.py").unlink()
            return [
                files([])
                | {"affected": ["test_module.py"], "affected_count": 1, "changed": ["module.py"]}
            ]
        return [files(rows)]

    monkeypatch.setattr(review_rank.shutil, "which", lambda _: "/bin/pkgrank")
    monkeypatch.setattr(review_rank, "_reports", reports)
    result = review_rank.rank_findings(tmp_path, [{"file": "module.py"}], 5)
    assert result["missing_files"] == ["test_module.py"]
    assert "tests_unavailable" in result and "candidate_tests" not in result


def test_report_identifies_replacement_launcher_at_same_path(tmp_path, monkeypatch):
    launcher = tmp_path / "pkgrank"
    source = tmp_path / "example.py"
    source.touch()
    monkeypatch.setattr(review_rank.shutil, "which", lambda _: str(launcher))
    monkeypatch.setattr(review_rank, "_reports", lambda *args: [files([row(source.name, 0)])])
    launcher.write_bytes(b"a")
    first = review_rank.rank_findings(tmp_path, [{"file": source.name}], 5)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"b")
    replacement.replace(launcher)
    second = review_rank.rank_findings(tmp_path, [{"file": source.name}], 5)
    assert first["producer"]["launcher_sha256"] != second["producer"]["launcher_sha256"]
    assert first["producer"]["name"] == second["producer"]["name"] == "pkgrank"
