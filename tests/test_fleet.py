"""Tests for the many-repository sweep: selection, clone cache, result cache, reporting."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from devguard import fleet as fl
from devguard.cli import app

SWEEPS = ["gitignore_audit", "pre_commit_audit"]


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", "/dev/null")
    monkeypatch.setenv("DEVGUARD_CACHE_DIR", str(tmp_path / "cache"))


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout.strip()


def _make_origin(base: Path, name: str, files: dict[str, str]) -> Path:
    repo = base / "origins" / name
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    for rel, text in files.items():
        (repo / rel).write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "first")
    return repo


def _remote(origin: Path) -> fl.RepoRef:
    return fl.RepoRef(name=f"owner/{origin.name}", url=f"file://{origin}")


def test_parse_target_forms(tmp_path: Path) -> None:
    assert fl.parse_target("octo/widget") == fl.RepoRef(
        name="octo/widget", url="https://github.com/octo/widget"
    )
    assert fl.parse_target("https://github.com/octo/widget.git/").name == "octo/widget"
    assert fl.parse_target("git@github.com:octo/widget.git").name == "octo/widget"
    local = _make_origin(tmp_path, "local", {"a.txt": "a\n"})
    assert fl.parse_target(str(local)).path == local.resolve()
    with pytest.raises(ValueError, match="not a git repository"):
        fl.parse_target(str(tmp_path))
    with pytest.raises(ValueError, match="owner/name"):
        fl.parse_target("not a repo")


def test_filter_repos_defaults_and_order() -> None:
    refs = [
        fl.RepoRef(name="o/old", url="u", pushed_at="2024-01-01T00:00:00Z"),
        fl.RepoRef(name="o/new", url="u", pushed_at="2025-06-01T00:00:00Z"),
        fl.RepoRef(name="o/fork", url="u", fork=True, pushed_at="2025-07-01T00:00:00Z"),
        fl.RepoRef(name="o/attic", url="u", archived=True),
        fl.RepoRef(name="o/empty", url="u", empty=True),
        fl.RepoRef(name="o/secret", url="u", visibility="private", pushed_at="2025-01-01"),
        fl.RepoRef(name="o/new", url="u", pushed_at="2025-06-01T00:00:00Z"),
    ]
    assert [r.name for r in fl.filter_repos(refs)] == ["o/new", "o/secret", "o/old"]
    assert [r.name for r in fl.filter_repos(refs, include_forks=True, limit=1)] == ["o/fork"]
    assert [r.name for r in fl.filter_repos(refs, pushed_since="2025-01-01")] == [
        "o/new",
        "o/secret",
    ]
    assert [r.name for r in fl.filter_repos(refs, match=["n*"], exclude=["o/old"])] == ["o/new"]
    # A ref with unknown visibility is not dropped by a visibility filter.
    assert "o/new" in [r.name for r in fl.filter_repos(refs, visibility="public")]
    assert "o/secret" not in [r.name for r in fl.filter_repos(refs, visibility="public")]


def test_extract_findings_reads_every_report_shape() -> None:
    reports = {
        "repo_lint": {"findings": [{"check": "ci_gaps", "severity": "low", "file": "ci.yml"}]},
        "local_dev": {"hits": [{"file_path": "a.pem", "reason": "deny_glob:**/*.pem"}]},
        "pre_commit_audit": {
            "repos": [{"findings": [{"check_id": "no_hook", "severity": "error", "message": "m"}]}]
        },
        "gitignore_audit": {"repos": [{"is_public": True, "missing_patterns": [".env files"]}]},
        "mcp_security_audit": {
            "findings": [{"check_id": "x", "severity": "WARNING", "line": 3, "file": "mcp.json"}]
        },
        "broken": ["not", "a", "dict"],
    }
    found = fl.extract_findings(reports)
    assert [(f["sweep"], f["check"], f["severity"]) for f in found] == [
        ("pre_commit_audit", "no_hook", "high"),
        ("local_dev", "deny_glob:**/*.pem", "medium"),
        ("mcp_security_audit", "x", "medium"),
        ("gitignore_audit", "gitignore_gap", "low"),
        ("repo_lint", "ci_gaps", "low"),
    ]
    assert found[2]["file"] == "mcp.json:3"


def test_exit_code_prefers_missed_coverage() -> None:
    def res(status: str, code: int, severity: str | None) -> fl.RepoResult:
        findings = [{"severity": severity, "sweep": "s", "check": "c"}] if severity else []
        return fl.RepoResult("r", None, "h", "", status, code, 0.0, findings)

    assert fl.fleet_exit_code([res("scanned", 0, None)], "high") == 0
    assert fl.fleet_exit_code([res("scanned", 2, "low")], "high") == 0
    assert fl.fleet_exit_code([res("scanned", 2, "low")], "low") == 2
    assert fl.fleet_exit_code([res("cached", 2, "critical")], "high") == 2
    assert fl.fleet_exit_code([res("cached", 2, "critical")], "never") == 0
    assert fl.fleet_exit_code([res("scanned", 2, "high"), res("error", 3, None)], "high") == 3
    assert fl.fleet_exit_code([res("scanned", 3, None)], "never") == 3


def test_result_key_changes_with_inputs(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yaml"
    spec.write_text("a: 1\n")
    base = dict(head="abc", sweeps=["b", "a"], spec_path=spec, full_history=False, name="o/r")
    key = fl.result_key(**base)
    assert key == fl.result_key(**{**base, "sweeps": ["a", "b"]})
    assert key != fl.result_key(**{**base, "head": "abd"})
    assert key != fl.result_key(**{**base, "sweeps": ["a"]})
    assert key != fl.result_key(**{**base, "full_history": True})
    assert key != fl.result_key(**{**base, "name": "o/other"})
    spec.write_text("a: 2\n")
    assert key != fl.result_key(**base)


def test_sync_repo_clones_once_then_fetches(tmp_path: Path) -> None:
    origin = _make_origin(tmp_path, "widget", {"a.txt": "one\n"})
    ref = _remote(origin)
    path, first = fl.sync_repo(ref)
    assert path == tmp_path / "cache" / "repos" / "owner" / "widget"
    assert (path / "a.txt").read_text() == "one\n"

    (path / "scratch.tmp").write_text("left behind by a scan\n")
    (origin / "a.txt").write_text("two\n")
    _git(origin, "commit", "-qam", "second")

    _, offline = fl.sync_repo(ref, refresh=False)
    assert offline == first
    _, second = fl.sync_repo(ref)
    assert second == _git(origin, "rev-parse", "HEAD") != first
    assert (path / "a.txt").read_text() == "two\n"
    assert not (path / "scratch.tmp").exists()


def test_sync_repo_replaces_a_broken_or_foreign_clone(tmp_path: Path) -> None:
    origin = _make_origin(tmp_path, "widget", {"a.txt": "one\n"})
    other = _make_origin(tmp_path, "gadget", {"b.txt": "other\n"})
    ref = _remote(origin)
    path, head = fl.sync_repo(ref)
    (path / ".git" / "HEAD").write_text("garbage\n")
    assert fl.sync_repo(ref) == (path, head)
    # Same cache slot, different remote: the old clone must not be reused.
    moved = fl.RepoRef(name=ref.name, url=f"file://{other}")
    path2, _ = fl.sync_repo(moved)
    assert path2 == path and (path / "b.txt").exists() and not (path / "a.txt").exists()


@pytest.mark.parametrize(
    "name", ["../..", "owner/..", "..", ".", "a/../../b", "/etc/passwd", "o/.git", "", "o//"]
)
def test_cached_clone_path_stays_inside_the_cache(tmp_path: Path, name: str) -> None:
    repos = (tmp_path / "cache" / "repos").resolve()
    dest = fl.cached_clone_path(fl.RepoRef(name=name, url="u")).resolve()
    assert dest.parent.parent == repos, dest
    assert not dest.name.startswith(".")


def test_hostile_url_cannot_delete_outside_the_cache(tmp_path: Path) -> None:
    keep = tmp_path / "keep.txt"
    keep.write_text("still here\n")
    (tmp_path / "cache").mkdir()
    ref = fl.parse_target(f"file://{tmp_path}/nope/../..")
    with pytest.raises(RuntimeError):
        fl.sync_repo(ref)
    assert keep.read_text() == "still here\n"


def test_sync_repo_reports_a_missing_remote(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="git clone failed"):
        fl.sync_repo(fl.RepoRef(name="o/missing", url=f"file://{tmp_path}/nope"))


def test_scan_fleet_scans_in_parallel_then_serves_from_cache(tmp_path: Path) -> None:
    origins = [
        _make_origin(tmp_path, "alpha", {"main.py": "print(1)\n"}),
        _make_origin(tmp_path, "beta", {"main.py": "print(2)\n", ".gitignore": "*.pyc\n"}),
    ]
    refs = [_remote(o) for o in origins] + [
        fl.RepoRef(name="owner/missing", url=f"file://{tmp_path}/nope")
    ]
    seen: list[str] = []
    first = fl.scan_fleet(refs, sweeps=SWEEPS, jobs=3, on_done=lambda r: seen.append(r.name))
    assert [r.name for r in first] == ["owner/alpha", "owner/beta", "owner/missing"]
    assert sorted(seen) == sorted(r.name for r in refs)
    assert [r.status for r in first] == ["scanned", "scanned", "error"]
    assert first[2].exit_code == 3 and "git clone failed" in first[2].errors[0]
    assert any(f["check"] == "no_pre_commit_config" for f in first[0].findings)

    second = fl.scan_fleet(refs, sweeps=SWEEPS, jobs=3)
    assert [r.status for r in second] == ["cached", "cached", "error"]
    assert second[0].findings == first[0].findings

    # A new commit invalidates only that repository's result.
    (origins[0] / "main.py").write_text("print(3)\n")
    _git(origins[0], "commit", "-qam", "change")
    third = fl.scan_fleet(refs[:2], sweeps=SWEEPS, jobs=2)
    assert [r.status for r in third] == ["scanned", "cached"]
    assert [r.status for r in fl.scan_fleet(refs[:2], sweeps=SWEEPS, use_cache=False)] == [
        "scanned",
        "scanned",
    ]

    report = fl.fleet_report(third, sweeps=SWEEPS, seconds=1.0)
    assert report["summary"]["repos"] == 2 and report["summary"]["cached"] == 1
    assert "reports" not in report["repos"][0]
    assert sum(report["summary"]["findings"].values()) == sum(len(r.findings) for r in third)


def test_dirty_local_checkout_is_never_served_from_cache(tmp_path: Path) -> None:
    local = _make_origin(tmp_path, "local", {"main.py": "print(1)\n"})
    ref = fl.RepoRef(name="local", path=local)
    assert fl.scan_fleet([ref], sweeps=SWEEPS)[0].status == "scanned"
    assert fl.scan_fleet([ref], sweeps=SWEEPS)[0].status == "cached"
    (local / "new.txt").write_text("uncommitted\n")
    assert fl.scan_fleet([ref], sweeps=SWEEPS)[0].status == "scanned"
    assert not (local / ".state").exists(), "a scan must not write into the checkout"


def test_child_crash_is_one_repo_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    origin = _make_origin(tmp_path, "alpha", {"main.py": "print(1)\n"})

    def killed(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], -9, "", "Killed\n")

    real_run = subprocess.run
    monkeypatch.setattr(
        fl.subprocess,
        "run",
        lambda cmd, *a, **k: killed() if "sweep" in cmd else real_run(cmd, *a, **k),
    )
    (res,) = fl.scan_fleet([_remote(origin)], sweeps=SWEEPS)
    assert res.status == "error" and "exited -9" in res.errors[0]
    monkeypatch.setattr(fl.subprocess, "run", real_run)
    # The failure was not cached.
    assert fl.scan_fleet([_remote(origin)], sweeps=SWEEPS)[0].status == "scanned"


def test_cli_dry_run_json_and_cache_commands(tmp_path: Path) -> None:
    runner = CliRunner()
    origin = _make_origin(tmp_path, "alpha", {"main.py": "print(1)\n"})
    listing = tmp_path / "repos.txt"
    listing.write_text(f"# comment\n{origin}\n")

    dry = runner.invoke(app, ["fleet", "--repos-file", str(listing), "--dry-run"])
    assert dry.exit_code == 0 and dry.stdout.startswith("alpha\t")

    out = tmp_path / "report.json"
    args = ["fleet", str(origin), "--format", "json", "--output", str(out), "--fail-on", "never"]
    run = runner.invoke(app, [*args, "--only", "gitignore_audit,pre_commit_audit"])
    assert run.exit_code == 0, run.output
    report = json.loads(out.read_text())
    assert report["summary"]["repos"] == 1 and report["repos"][0]["status"] == "scanned"
    assert report["sweeps"] == ["gitignore_audit", "pre_commit_audit"]

    text = runner.invoke(
        app,
        [
            "fleet",
            str(origin),
            "--only",
            "pre_commit_audit",
            "--details",
            "medium",
            "--fail-on",
            "medium",
        ],
    )
    assert text.exit_code == 2
    assert "no_pre_commit_config" in text.output and "1 repositories" in text.output

    info = runner.invoke(app, ["cache", "info", "--json"])
    assert json.loads(info.stdout)["results"] == 2
    assert runner.invoke(app, ["cache", "clear", "--results"]).exit_code == 0
    assert json.loads(runner.invoke(app, ["cache", "info", "--json"]).stdout)["results"] == 0


def test_cli_rejects_bad_input(tmp_path: Path) -> None:
    runner = CliRunner()
    assert runner.invoke(app, ["fleet"]).exit_code == 1
    assert runner.invoke(app, ["fleet", "o/r", "--only", "nope"]).exit_code != 0
    assert runner.invoke(app, ["fleet", "o/r", "--fail-on", "loud"]).exit_code != 0
    assert runner.invoke(app, ["fleet", str(tmp_path / "missing dir")]).exit_code == 1


def test_fleet_retries_invalid_spec_instead_of_reporting_clean(tmp_path: Path) -> None:
    repo = _make_origin(tmp_path, "docs", {"README.md": "fixture\n"})
    spec = tmp_path / "broken.yaml"
    spec.write_text("name: [\n")
    sweeps = ["repo_hygiene"]
    key = fl.result_key(
        head=_git(repo, "rev-parse", "HEAD"),
        sweeps=sweeps,
        spec_path=spec,
        full_history=False,
        name=repo.name,
    )
    # A cache created by the previous fleet implementation.
    fl._write_cached_result(fl.cache_root(), key, {"exit_code": 2, "reports": {}})
    runner = CliRunner()
    args = ["fleet", str(repo), "--only", "repo_hygiene", "--spec", str(spec), "--format", "json"]
    for _ in range(2):
        run = runner.invoke(app, args)
        assert run.exit_code == 3
        report = json.loads(run.stdout)
        assert report["summary"]["errors"] == 1
        assert report["summary"]["clean"] == report["summary"]["cached"] == 0
        assert "Invalid sweep spec" in report["repos"][0]["errors"][0]


@pytest.mark.parametrize("name", ["missing.yaml", "devguard.spec.yaml", "directory"])
def test_explicit_spec_must_be_a_file(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    repo = _make_origin(tmp_path, "docs", {"README.md": "fixture\n"})
    (tmp_path / "directory").mkdir()
    fallback = tmp_path / "personal.yaml"
    fallback.write_text("{}\n")
    monkeypatch.setenv("DEVGUARD_SPEC", str(fallback))
    args = ["fleet", str(repo), "--only", "repo_hygiene", "--dry-run"]
    runner = CliRunner()
    assert runner.invoke(app, args).exit_code == 0
    run = runner.invoke(app, [*args, "--spec", name])
    assert run.exit_code != 0
    assert name in run.output


def test_partial_report_is_neither_clean_nor_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _make_origin(tmp_path, "docs", {"README.md": "fixture\n"})
    ref = fl.parse_target(str(repo))
    sweeps = ["repo_hygiene"]
    results = iter(
        [
            (3, {"repo_hygiene": {"errors": ["temporarily unavailable"]}}, ""),
            (0, {"repo_hygiene": {"findings": []}}, ""),
        ]
    )
    monkeypatch.setattr(fl, "run_sweeps", lambda *_: next(results))
    first = fl.scan_fleet([ref], sweeps=sweeps)
    summary = fl.fleet_report(first, sweeps=sweeps, seconds=0.0)["summary"]
    assert summary["incomplete"] == 1
    assert summary["clean"] == 0
    assert fl.fleet_exit_code(first, "never") == 3
    recovered = fl.scan_fleet([ref], sweeps=sweeps)
    assert recovered[0].status == "scanned"
    assert fl.fleet_exit_code(recovered, "high") == 0
    assert fl.scan_fleet([ref], sweeps=sweeps)[0].status == "cached"
