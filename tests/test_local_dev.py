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


def test_key_file_found_by_content_and_benign_npmrc_skipped(tmp_path: Path) -> None:
    repo = tmp_path / "root" / "r"
    repo.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    pem = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n"
    (repo / "deploy_key").write_text(pem)
    (repo / ".npmrc").write_text("save-exact=true\n")
    (repo / "web").mkdir()
    (repo / "web" / ".npmrc").write_text("//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)

    hits, _ = sweep_dev_repos(tmp_path / "root", max_depth=2)

    assert sorted((h.file_path, h.reason) for h in hits) == [
        ("deploy_key", "private_key_content"),
        ("web/.npmrc", "deny_glob:**/.npmrc"),
    ]


def _fork_repo(root: Path, name: str, origin: str, upstream: str | None) -> Path:
    repo = root / name
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", origin], check=True)
    if upstream:
        subprocess.run(["git", "-C", str(repo), "remote", "add", "upstream", upstream], check=True)
    _track(repo, [".env"])
    return repo


def test_fork_hits_are_upstream_owned(tmp_path: Path) -> None:
    own = _fork_repo(tmp_path, "own", "git@github.com:example-me/own.git", None)
    fork = _fork_repo(
        tmp_path,
        "fork",
        "git@github.com:example-me/fork.git",
        "https://github.com/example-upstream/fork.git",
    )

    hits, meta = sweep_dev_repos(tmp_path, max_depth=1)

    by_repo = {Path(h.repo_path).name: h.upstream_owned for h in hits}
    assert by_repo == {"own": False, "fork": True}
    assert meta["upstream_owned_repos"] == [str(fork)]
    assert (meta["actionable_hits"], meta["upstream_owned_hits"]) == (1, 1)
    assert str(own) not in meta["upstream_owned_repos"]


def test_configured_owner_marks_foreign_origin(tmp_path: Path) -> None:
    _fork_repo(tmp_path, "mine", "https://github.com/Example-Me/mine", None)
    _fork_repo(tmp_path, "org", "https://git.example.net/example-org/org.git", None)
    _fork_repo(tmp_path, "clone", "https://github.com/example-other/clone.git", None)

    unconfigured, _ = sweep_dev_repos(tmp_path, max_depth=1)
    hits, _ = sweep_dev_repos(tmp_path, max_depth=1, owners=["example-me", "example-org"])

    assert not any(h.upstream_owned for h in unconfigured)
    assert {Path(h.repo_path).name: h.upstream_owned for h in hits} == {
        "mine": False,
        "org": False,
        "clone": True,
    }


def test_sweep_dev_cli_exit_ignores_upstream_hits(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from devguard import cli

    root = tmp_path / "ws"
    root.mkdir()
    _fork_repo(
        root,
        "fork",
        "git@github.com:example-me/fork.git",
        "git@github.com:example-upstream/fork.git",
    )
    out = tmp_path / "report.json"
    base = ["sweep-dev", "--dev-root", str(root), "-o", str(out), "--spec", str(tmp_path / "x")]

    assert CliRunner().invoke(cli.app, base).exit_code == 0
    assert CliRunner().invoke(cli.app, base + ["--include-upstream"]).exit_code == 2
    assert json.loads(out.read_text())["hits"][0]["upstream_owned"] is True


def test_sweep_dev_reads_owner_from_spec(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from devguard import cli

    root = tmp_path / "ws"
    root.mkdir()
    _fork_repo(root, "clone", "https://github.com/example-other/clone.git", None)
    spec = tmp_path / "devguard.spec.yaml"
    spec.write_text("name: t\nsweeps:\n  local_dev:\n    owners: [example-me]\n")
    base = ["sweep-dev", "--dev-root", str(root), "-o", str(tmp_path / "r.json")]

    assert CliRunner().invoke(cli.app, base + ["--spec", str(tmp_path / "none")]).exit_code == 2
    assert CliRunner().invoke(cli.app, base + ["--spec", str(spec)]).exit_code == 0


def test_fork_remote_name_counts_as_push_remote(tmp_path: Path) -> None:
    repo = tmp_path / "forked"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    for name, url in (
        ("fork", "https://github.com/example-me/forked.git"),
        ("upstream", "https://github.com/example-upstream/forked.git"),
    ):
        subprocess.run(["git", "-C", str(repo), "remote", "add", name, url], check=True)
    _track(repo, [".env"])

    hits, _ = sweep_dev_repos(tmp_path, max_depth=1)

    assert [h.upstream_owned for h in hits] == [True]
