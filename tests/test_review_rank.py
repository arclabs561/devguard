import json
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired

import pytest

from devguard import fleet, review_rank


def row(path, reach, role="source"):
    return {"file": path, "dependents": reach, "role": role}


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
