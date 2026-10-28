"""The CLI requires explicit inputs and preserves advisory/incomplete outcomes."""

import json
import socket
import subprocess

import pytest
from typer.testing import CliRunner

from devguard.cli import app


@pytest.mark.parametrize("missing", ["--repo", "--document", "--package-root"])
def test_requires_every_scope_argument(tmp_path, missing):
    arguments = {"--repo": str(tmp_path), "--document": "README.md", "--package-root": "."}
    argv = ["doc-commands"]
    for option, value in arguments.items():
        if option != missing:
            argv.extend([option, value])
    assert CliRunner().invoke(app, argv).exit_code == 2


@pytest.mark.parametrize(
    "body,expected_exit,checked,findings,skipped",
    [
        ("```sh\nnpm run missing\n```", 0, 1, 1, 0),
        ("```sh\ncd elsewhere\nnpm run missing\n```", 3, 0, 0, 1),
    ],
)
def test_cli_advisory_and_incomplete_without_execution(
    tmp_path, monkeypatch, body, expected_exit, checked, findings, skipped
):
    def forbidden(*args, **kwargs):
        pytest.fail("documentation checks must not execute subprocesses or use network")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    package = tmp_path / "package"
    package.mkdir()
    (package / "package.json").write_text('{"scripts":{"check":"touch SHOULD_NOT_EXIST"}}')
    (tmp_path / "README.md").write_text(body)
    (tmp_path / "usage.md").write_text("# Plain documentation")
    result = CliRunner().invoke(
        app,
        [
            "doc-commands",
            "--repo",
            str(tmp_path),
            "--package-root",
            "package",
            "--document",
            "README.md",
            "--document",
            "usage.md",
        ],
    )
    assert result.exit_code == expected_exit, result.output
    report = json.loads(result.stdout)
    assert report["commands_checked"] == checked
    assert len(report["findings"]) == findings
    assert len(report["skipped"]) == skipped
    assert report["errors"] == []
    assert report["scope"]["package_root"] == "package"
    assert not (tmp_path / ".state").exists()
    assert not (package / "SHOULD_NOT_EXIST").exists()


def test_scope_error_is_sanitized_json(tmp_path):
    result = CliRunner().invoke(
        app,
        [
            "doc-commands",
            "--repo",
            str(tmp_path / "sensitive-scope-name"),
            "--package-root",
            ".",
            "--document",
            "README.md",
        ],
    )
    assert result.exit_code == 3
    report = json.loads(result.stdout)
    assert report["errors"]
    assert report["commands_checked"] == 0
    assert "sensitive-scope-name" not in result.output
