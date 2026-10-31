"""public_text_leak: coordination text in public commit/PR text, minus allowed attribution."""

import subprocess
from pathlib import Path

import pytest

from devguard.sweeps import public_text_leak as ptl
from devguard.sweeps.public_text_leak import (
    compile_patterns,
    parse_github_remote,
    scan_public_text_leaks,
    scan_text,
)

SESSION_ID = "01ABCDEFGHIJKLMNOPQRSTUV"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _repo(root: Path, name: str, owner: str, messages: list[str]) -> Path:
    repo = root / name
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "dev@example.invalid")
    _git(repo, "config", "user.name", "Dev")
    _git(repo, "remote", "add", "origin", f"git@github.com:{owner}/{name}.git")
    for i, msg in enumerate(messages):
        (repo / f"f{i}").write_text(str(i))
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", msg)
    return repo


@pytest.mark.parametrize(
    "text",
    [
        "fix: retry ses_AbCdEf123456 timeout",
        "docs: note from the Claude session",
        "chore: ported from opencode",
        "ci: let the subagent rebase",
        "refactor: lane record update",
        "fix: claim-release-wave-3",
        "docs: handoff to next owner",
        "fix: coordinate with peer session",
    ],
)
def test_default_patterns_flag_coordination_text(text: str) -> None:
    patterns, errors = compile_patterns(None, [])
    assert errors == []
    assert len(scan_text(text, patterns)) == 1


@pytest.mark.parametrize(
    "text",
    [
        "perf: each SIMD lane reads one packed word",
        "ci: pin thiserror for the msrv lane",
        "deps: bump jwt-iss-claim-validation",
        "fix: flagged as not claim-worthy",
    ],
)
def test_default_patterns_skip_ordinary_wording(text: str) -> None:
    patterns, _ = compile_patterns(None, [])
    assert scan_text(text, patterns) == []


def test_attribution_trailer_and_trailing_pr_url_are_allowed() -> None:
    # A pattern that would match the session URL proves the allowlist is what clears it.
    patterns, _ = compile_patterns([*ptl.DEFAULT_PATTERNS, r"claude\.ai/code/session_"], [])
    assert len(scan_text(f"see https://claude.ai/code/session_{SESSION_ID}", patterns)) == 1
    commit = f"fix: bound parser\n\nClaude-Session: https://claude.ai/code/session_{SESSION_ID}\n"
    pr_body = f"Bounds the parser.\n\nhttps://claude.ai/code/session_{SESSION_ID}\n"
    assert scan_text(commit, patterns) == []
    assert scan_text(pr_body, patterns, pr_body=True) == []
    # The trailer form with a free-text note is not the allowed shape.
    assert len(scan_text("Claude session: worked on this", patterns)) == 1


def test_bare_session_url_only_allowed_at_end_of_pr_body() -> None:
    patterns, _ = compile_patterns([r"claude\.ai/code/session_"], [])
    body = f"https://claude.ai/code/session_{SESSION_ID}\nMore text after.\n"
    assert len(scan_text(body, patterns, pr_body=True)) == 1


def test_private_names_and_allow_patterns() -> None:
    patterns, _ = compile_patterns(None, ["example-private"])
    allow = [ptl.re.compile(r"^Reviewed-by:")]
    assert len(scan_text("deploy via example-private host", patterns)) == 1
    assert len(scan_text("ssh box.example-private.example.net", patterns)) == 1
    assert scan_text("Reviewed-by: example-private bot", patterns, allow=allow) == []
    # Word boundary: a longer name is not a hit.
    assert scan_text("example-private-tools is public", patterns) == []


def test_excerpt_redacts_the_match() -> None:
    patterns, _ = compile_patterns(None, [])
    hit = scan_text("retry ses_AbCdEf123456 timeout", patterns)[0]
    assert "ses_AbCdEf123456" not in hit["excerpt"]
    assert hit["excerpt"].startswith("retry ses***")


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("git@github.com:example-owner/demo.git", ("example-owner", "demo")),
        ("https://github.com/example-owner/demo", ("example-owner", "demo")),
        ("https://token@github.com/example-owner/demo.git", ("example-owner", "demo")),
        ("https://gitlab.com/example-owner/demo.git", None),
    ],
)
def test_parse_github_remote(url: str, expected: tuple[str, str] | None) -> None:
    assert parse_github_remote(url) == expected


def test_scan_only_public_repos_and_reports_location(tmp_path: Path) -> None:
    pub = _repo(tmp_path, "pub", "example-owner", ["fix: handoff notes", "fix: plain change"])
    _repo(tmp_path, "priv", "example-owner", ["fix: handoff notes"])

    report, errors = scan_public_text_leaks(
        dev_root=tmp_path,
        max_depth=1,
        public_repo_lister=lambda owner, timeout: {"example-owner/pub"},
    )

    assert errors == []
    assert report["scope"]["public_repos_scanned"] == 1
    assert report["summary"]["total_findings"] == 1
    finding = report["repos"][0]["findings"][0]
    sha = subprocess.run(
        ["git", "-C", str(pub), "rev-list", "--max-count=1", "HEAD~1"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert finding["location"] == f"commit {sha[:12]}"
    assert finding["pattern"] == r"(?i)\bhand-?off\b"


def test_visibility_failure_is_an_error_not_clean(tmp_path: Path) -> None:
    _repo(tmp_path, "pub", "example-owner", ["fix: handoff notes"])

    def broken(owner: str, timeout: int) -> set[str]:
        raise RuntimeError("gh repo failed (exit 1)")

    report, errors = scan_public_text_leaks(
        dev_root=tmp_path, max_depth=1, public_repo_lister=broken
    )
    assert report["scope"]["public_repos_scanned"] == 0
    assert errors == ["visibility lookup failed for owner example-owner: gh repo failed (exit 1)"]


def test_pr_bodies_and_comments_via_gh(tmp_path: Path, monkeypatch) -> None:
    _repo(tmp_path, "pub", "example-owner", ["fix: plain change"])
    items = [
        {
            "number": 7,
            "body": f"Adds a check.\n\nhttps://claude.ai/code/session_{SESSION_ID}",
            "comments": [{"id": "IC_1", "body": "the subagent should rerun"}],
        }
    ]
    monkeypatch.setattr(ptl, "_gh_items", lambda *a, **k: items)

    report, errors = scan_public_text_leaks(
        dev_root=tmp_path,
        max_depth=1,
        include_prs=True,
        public_repo_lister=lambda owner, timeout: {"example-owner/pub"},
    )

    assert errors == []
    assert [f["location"] for f in report["repos"][0]["findings"]] == ["pr #7 comment IC_1"]
