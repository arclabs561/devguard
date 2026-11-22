"""docs_quality: findings are normalized, and every coverage gap is reported."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from devguard import cli
from devguard.sweeps.docs_quality import audit_docs_quality

VALE_ALERTS = {"README.md": [{"Line": 3, "Check": "Style.Weasel", "Message": "Avoid 'very'."}]}
READCOST_OUT = [
    {"path": "docs/guide.md", "findings": [{"line": 2, "feature": "inline-list", "message": "x"}]}
]


def _tool(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text(f"#!{sys.executable}\nimport json, sys, time\n{body}\n")
    path.chmod(0o755)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "docs").mkdir(parents=True)
    (root / "README.md").write_text("# Demo\n\nThis is very simple.\n")
    (root / "docs" / "guide.md").write_text("# Guide\n\nUse a, b, c, and d.\n")
    (root / "docs" / "notes.txt").write_text("not markdown\n")
    (root / "CHANGELOG.md").write_text("# Changelog\n")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    return root


@pytest.fixture
def bin_dir(tmp_path: Path, monkeypatch) -> Path:
    """A PATH holding only git, so real vale/readcost/docs-check never run."""
    d = tmp_path / "bin"
    d.mkdir()
    git = shutil.which("git")
    assert git
    os.symlink(git, d / "git")
    monkeypatch.setenv("PATH", str(d))
    return d


def _fake_direct_tools(bin_dir: Path, styles: bool = True) -> None:
    ls_config = {"GBaseStyles": ["Style"]} if styles else {"GBaseStyles": [], "SBaseStyles": {}}
    _tool(
        bin_dir,
        "vale",
        f"if sys.argv[1] == 'ls-config':\n    print(json.dumps({ls_config!r}))\n"
        f"else:\n    print(json.dumps({VALE_ALERTS!r}))",
    )
    _tool(
        bin_dir,
        "readcost",
        f"out = {READCOST_OUT!r}\n"
        "out.extend({'path': p, 'findings': []} for p in sys.argv[6:] if p != 'docs/guide.md')\n"
        "print(json.dumps(out))",
    )


def test_missing_tools_are_incomplete_not_clean(repo: Path, bin_dir: Path) -> None:
    report, errors = audit_docs_quality(dev_root=repo, max_depth=0, engine="auto")

    assert report["scope"]["engine"] == "direct"
    assert report["summary"]["files_checked"] == 0
    assert report["summary"]["files_selected"] == 2
    assert report["summary"]["total_findings"] == 0
    assert report["summary"]["coverage_complete"] is False
    assert {e.split(": ", 1)[1] for e in errors} == {
        "vale: not installed",
        "readcost: not installed",
    }


def test_direct_engine_normalizes_findings(repo: Path, bin_dir: Path) -> None:
    _fake_direct_tools(bin_dir)

    report, errors = audit_docs_quality(dev_root=repo, max_depth=0, engine="direct")

    assert errors == []
    assert report["summary"]["coverage_complete"] is True
    messages = sorted(f["message"] for f in report["repos"][0]["findings"])
    checks = sorted(f["check"] for f in report["repos"][0]["findings"])
    assert messages == ["README.md:3: Avoid 'very'.", "docs/guide.md:2: x"]
    assert checks == ["docs_quality:readcost/inline-list", "docs_quality:vale/Style.Weasel"]


def test_changelog_is_opt_in(repo: Path, bin_dir: Path) -> None:
    _fake_direct_tools(bin_dir)
    without, _ = audit_docs_quality(dev_root=repo, max_depth=0, engine="direct")
    with_cl, _ = audit_docs_quality(
        dev_root=repo, max_depth=0, engine="direct", include_changelog=True
    )
    assert without["summary"]["files_checked"] == 2
    assert with_cl["summary"]["files_checked"] == 3


def test_vale_without_styles_is_incomplete(repo: Path, bin_dir: Path) -> None:
    _fake_direct_tools(bin_dir, styles=False)

    report, errors = audit_docs_quality(dev_root=repo, max_depth=0, engine="direct")

    assert any("vale: no styles configured" in e for e in errors)
    assert report["summary"]["coverage_complete"] is False


def test_timeout_is_incomplete(repo: Path, bin_dir: Path) -> None:
    _fake_direct_tools(bin_dir)
    _tool(bin_dir, "readcost", "time.sleep(5)")

    report, errors = audit_docs_quality(dev_root=repo, max_depth=0, engine="direct", timeout_s=1)

    assert any("readcost: timed out" in e for e in errors)
    assert report["summary"]["incomplete_repos"] == 1


def test_wrapper_engine_reads_docs_check_json(repo: Path, bin_dir: Path) -> None:
    body = (
        "out = [{'path': p, 'findings': [{'tool': 'vale', 'line': 1, 'rule': 'R', "
        "'message': 'm'}], 'unavailable': ['readcost: not installed'] if 'guide' in p else []}"
        " for p in sys.argv[2:]]\nprint(json.dumps(out))\nsys.exit(2)"
    )
    _tool(bin_dir, "docs-check", body)

    report, errors = audit_docs_quality(dev_root=repo, max_depth=0, engine="auto")

    assert report["scope"]["engine"] == "wrapper"
    assert report["summary"]["total_findings"] == 2
    assert errors == ["repo: docs/guide.md: readcost: not installed"]


def test_cli_exit_3_on_incomplete_coverage(repo: Path, bin_dir: Path, tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli.app,
        ["sweep", "--spec", str(tmp_path / "none.yaml"), "--repo", str(repo)]
        + ["--only", "docs_quality", "--format", "json"],
    )
    assert result.exit_code == 3, result.output
    payload = json.loads(result.stdout[result.stdout.index("{") :])
    assert payload["docs_quality"]["summary"]["coverage_complete"] is False


def test_doctor_lists_docs_tools(bin_dir: Path) -> None:
    result = CliRunner().invoke(cli.app, ["doctor"], env={"COLUMNS": "200"})
    assert result.exit_code == 0
    rows = [line for line in result.output.splitlines() if "docs_quality" in line]
    assert len(rows) == 2
    assert all("missing" in row for row in rows)


def test_tool_failure_is_incomplete_with_detail(repo: Path, bin_dir: Path) -> None:
    _fake_direct_tools(bin_dir)
    _tool(bin_dir, "readcost", "sys.stderr.write('model missing\\n'); sys.exit(2)")

    report, errors = audit_docs_quality(dev_root=repo, max_depth=0, engine="direct")

    assert errors == ["repo: readcost: exit 2: model missing"]
    assert report["summary"]["coverage_complete"] is False


@pytest.mark.parametrize("engine", ["readcost", "vale"])
def test_selected_tool_checks_markdown_alone(repo: Path, bin_dir: Path, engine: str) -> None:
    from devguard.fleet import extract_findings

    _fake_direct_tools(bin_dir)
    (bin_dir / ("vale" if engine == "readcost" else "readcost")).unlink()
    report, errors = audit_docs_quality(dev_root=repo, max_depth=0, engine=engine)
    assert not errors and report["summary"]["coverage_complete"]
    assert report["scope"]["engine"] == engine
    (finding,) = extract_findings({"docs_quality": report})
    assert finding["file"] == ("docs/guide.md:2" if engine == "readcost" else "README.md:3")
    (bin_dir / engine).unlink()
    report, errors = audit_docs_quality(dev_root=repo, max_depth=0, engine=engine)
    assert not report["summary"]["coverage_complete"]
    assert errors == [f"repo: {engine}: not installed"]


def test_cap_oversize_and_actual_tool_coverage(repo: Path, bin_dir: Path) -> None:
    _fake_direct_tools(bin_dir)
    (repo / "docs" / "big.md").write_bytes(b"a" * (256 * 1024 + 1))
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    report, errors = audit_docs_quality(
        dev_root=repo, max_depth=0, engine="vale", max_files_per_repo=1
    )
    assert not errors
    summary = report["summary"]
    assert summary["files_eligible"] == 2
    assert summary["files_selected"] == summary["files_checked"] == 1
    assert summary["files_oversized"] == summary["files_omitted_by_limit"] == 1
    assert not summary["coverage_complete"]
    assert report["repos"][0]["omitted_by_limit"] == ["docs/guide.md"]
    assert report["repos"][0]["oversized"] == ["docs/big.md"]


@pytest.mark.parametrize(("engine", "name"), [("readcost", "readcost"), ("wrapper", "docs-check")])
def test_missing_per_file_output_is_partial(
    repo: Path, bin_dir: Path, engine: str, name: str
) -> None:
    _tool(bin_dir, name, 'print("[]")')
    report, errors = audit_docs_quality(dev_root=repo, max_depth=0, engine=engine)
    assert len(errors) == 2
    assert report["summary"]["files_checked"] == 0
    assert report["summary"]["files_selected"] == 2
    assert not report["summary"]["coverage_complete"]


@pytest.mark.parametrize("engine", ["vale", "readcost", "wrapper"])
def test_stale_producer_rows_cannot_create_findings(repo: Path, bin_dir: Path, engine: str):
    names = ["./README.md", str(repo / "docs/guide.md"), "../other/stale.md"]
    if engine == "vale":
        record = {"Line": 4, "Check": "test", "Message": "stale"}
        outputs = {path: [record] if i == 2 else [] for i, path in enumerate(names)}
        _tool(
            bin_dir,
            engine,
            f"print(json.dumps({{'GBaseStyles': ['Style']}} if sys.argv[1]=='ls-config' else {outputs!r}))",
        )
    else:
        record = {
            "line": 4,
            "feature": "test",
            "tool": "readcost",
            "rule": "test",
            "message": "stale",
        }
        outputs = [
            {"path": p, "findings": [record] if i == 2 else [], "unavailable": []}
            for i, p in enumerate(names)
        ]
        _tool(
            bin_dir,
            "docs-check" if engine == "wrapper" else engine,
            f"print(json.dumps({outputs!r}))",
        )
    data, errors = audit_docs_quality(dev_root=repo, max_depth=0, engine=engine)
    assert len(errors) == 1 and "unselected file" in errors[0]
    assert not data["summary"]["coverage_complete"]
    assert data["summary"]["total_findings"] == 0
    assert data["summary"]["files_checked"] == (0 if engine == "vale" else 2)
