"""Runtime artifact policy tests using synthetic Git-tracked files."""

import json
import subprocess
from dataclasses import asdict
from pathlib import Path

import pytest

from devguard.sweeps.local_dev import DEFAULT_DENY_GLOBS, sweep_dev_repos


@pytest.fixture
def tracked_repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    return tmp_path


def _track(repo: Path, names: list[str]) -> None:
    for name in names:
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("synthetic runtime payload\n")
    subprocess.run(["git", "-C", str(repo), "add", "-f", "--", *names], check=True)


@pytest.mark.parametrize("prefix", ["", "nested/"])
def test_runtime_email_artifacts_are_flagged(tracked_repo: Path, prefix: str) -> None:
    names = [
        prefix + name
        for name in (
            ".guardian-email-history.json",
            ".guardian-email-thread",
            ".devguard-email-history.json",
            ".devguard-email-thread",
        )
    ]
    _track(tracked_repo, names + [prefix + ".env.example", prefix + "README.md"])

    hits, meta = sweep_dev_repos(tracked_repo, max_depth=0)

    assert meta["repos_scanned"] == 1
    assert len(hits) == 4
    assert {hit.file_path for hit in hits} == set(names)
    assert all(hit.reason.startswith("deny_glob:") for hit in hits)
    assert "synthetic runtime payload" not in json.dumps([asdict(hit) for hit in hits])


def test_custom_runtime_policy_preserves_defaults(tracked_repo: Path) -> None:
    _track(
        tracked_repo,
        ["exports/session-history.json", ".guardian-email-thread", ".env.example", "README.md"],
    )
    defaults, _ = sweep_dev_repos(tracked_repo, max_depth=0)
    assert {hit.file_path for hit in defaults} == {".guardian-email-thread"}

    # The spec-driven CLI appends configured patterns to these defaults.
    hits, _ = sweep_dev_repos(
        tracked_repo,
        deny_globs=[*DEFAULT_DENY_GLOBS, "exports/session-history.json"],
        max_depth=0,
    )

    assert len(hits) == 2
    assert {hit.file_path for hit in hits} == {
        "exports/session-history.json",
        ".guardian-email-thread",
    }


def test_symlink_outside_repo_is_reported_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "big.bin").write_bytes(b"\0" * 2048)
    repo = tmp_path / "root" / "symrepo"
    repo.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "big.bin").symlink_to(outside / "big.bin")
    (repo / "docs").mkdir()
    (repo / "docs" / "README.md").write_text("readme\n")
    (repo / "README.md").symlink_to("docs/README.md")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)

    hits, _ = sweep_dev_repos(tmp_path / "root", max_blob_bytes=1024, max_depth=2)

    # The escaping link is reported by its own size; the in-repo link is fine.
    assert [(h.file_path, h.reason) for h in hits] == [("big.bin", "symlink_escapes_repo")]
    assert hits[0].size_bytes is not None and hits[0].size_bytes < 1024
