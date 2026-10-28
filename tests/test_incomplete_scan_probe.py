"""CLI regressions for visible, sanitized repository-inspection failures."""

import json
import os
import subprocess
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from devguard.cli import app
from devguard.sweeps import repo_hygiene


@pytest.mark.parametrize(
    "failure",
    [
        "complete",
        "history_present",
        "git_nonzero",
        "ignored_nonzero",
        "git_read_error",
        "git_timeout",
        "rev_list_nonzero",
        "cat_file_nonzero",
    ],
)
def test_incomplete_scan_probe(tmp_path, monkeypatch, failure):
    repo = tmp_path / "synthetic"
    repo.mkdir()
    real_run = subprocess.run
    env = {"PATH": os.environ["PATH"], "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    if "RUSTC_WRAPPER" in os.environ:
        env["RUSTC_WRAPPER"] = os.environ["RUSTC_WRAPPER"]
    real_run(["git", "init", "--quiet", str(repo)], env=env, check=True)
    content = "x" * (6 * 1024 * 1024) if failure == "history_present" else "# Synthetic fixture\n"
    (repo / "README.md").write_text(content, encoding="utf-8")
    real_run(["git", "-C", str(repo), "add", "README.md"], env=env, check=True)
    real_run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Synthetic Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--quiet",
            "-m",
            "synthetic fixture",
        ],
        env=env,
        check=True,
    )
    monkeypatch.chdir(tmp_path)
    calls = []
    operations = set()

    def run(argv, *args, **kwargs):
        assert argv[0] == "git", "probe forbids non-Git subprocesses"
        assert str(repo) in argv or str(kwargs.get("cwd", "")) == str(repo)
        operations.add(argv[3])
        if failure == "rev_list_nonzero":
            selected = "rev-list" in argv
        elif failure == "cat_file_nonzero":
            selected = "cat-file" in argv
        else:
            selected = "ls-files" in argv and (failure != "ignored_nonzero" or "--ignored" in argv)
        if selected and failure not in {"complete", "history_present"}:
            calls.append(list(argv))
            if failure == "git_read_error":
                raise PermissionError("private-config-payload " + str(repo))
            if failure == "git_timeout":
                raise subprocess.TimeoutExpired(argv, 60, stderr=b"private-config-payload")
            return subprocess.CompletedProcess(
                argv, 128, stdout=b"", stderr=b"private-config-payload"
            )
        return real_run(argv, *args, **kwargs)

    with patch.dict(os.environ, env, clear=True), patch.object(repo_hygiene.subprocess, "run", run):
        report, errors = repo_hygiene.sweep_repo_hygiene(dev_root=repo, max_depth=0)
        result = CliRunner().invoke(
            app,
            [
                "sweep",
                "--repo",
                str(repo),
                "--only",
                "repo_hygiene",
                "--format",
                "json",
                "--spec",
                str(tmp_path / "absent.yaml"),
            ],
        )
    expected_exit = {"complete": 0, "history_present": 2}.get(failure, 3)
    assert result.exit_code == expected_exit, result.output
    cli = json.loads(result.stdout)["repo_hygiene"]
    assert report["scope"]["repos_scanned"] == cli["scope"]["repos_scanned"] == 1
    expected_findings = 1 if failure == "history_present" else 0
    assert (
        report["summary"]["total_findings"] == cli["summary"]["total_findings"] == expected_findings
    )
    if failure == "history_present":
        finding = cli["repos"][0]["findings"][0]
        assert finding["check"] == "history_bloat"
        assert finding["files"] == ["README.md (6.0 MiB)"]
    expected = 0 if failure in {"complete", "history_present"} else 1
    assert len(errors) == len(cli["errors"]) == expected
    assert bool(calls) == (failure not in {"complete", "history_present"})
    assert errors == cli["errors"]
    for error in errors:
        assert error.startswith("git ")
        assert " inspection " in error
        assert "private-config-payload" not in error
        assert str(repo) not in error
        assert len(error) < 100
    if failure in {"complete", "history_present"}:
        assert {"ls-files", "rev-list", "cat-file"} <= operations
