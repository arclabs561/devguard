"""Selector errors must precede work, while valid selection keeps its semantics."""

import json
import socket
import subprocess

import pytest
from click import unstyle
from pydantic_settings import BaseSettings
from typer.testing import CliRunner

from devguard import cli, config, spec, sweeps
from devguard.sweeps import local_dev, publish_audit


@pytest.fixture
def offline(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("selector test attempted work outside its offline fixture")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(BaseSettings, "__init__", forbidden)
    monkeypatch.setattr(config, "get_settings", forbidden)
    monkeypatch.setattr(cli, "get_settings", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(sweeps, "default_dev_root", forbidden)
    monkeypatch.setattr(cli, "_clone_repo", forbidden)
    return forbidden


@pytest.mark.parametrize("force_color", [False, True])
@pytest.mark.parametrize("format", ["text", "json", "sarif"])
@pytest.mark.parametrize("repo", [None, "https://github.com/example/fixture", "synthetic-repo"])
@pytest.mark.parametrize(
    "selectors",
    [
        ["--only", "unknown_fixture"],
        ["--only", "local_dev,unknown_fixture"],
        ["--only", "local_dev", "--only", "unknown_fixture,unknown_fixture"],
    ],
)
def test_unknown_selector_rejected_before_any_work(
    monkeypatch, offline, format, repo, selectors, force_color
):
    if force_color:
        monkeypatch.setenv("FORCE_COLOR", "1")
        monkeypatch.delenv("NO_COLOR", raising=False)
    else:
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.setenv("NO_COLOR", "1")
    # Typer caches terminal policy when rich_utils is first imported. Select
    # the actual error-console mode, independent of earlier tests/imports.
    from typer import rich_utils

    monkeypatch.setattr(rich_utils, "FORCE_TERMINAL", force_color)
    monkeypatch.setattr(rich_utils, "COLOR_SYSTEM", "standard" if force_color else None)
    monkeypatch.setattr(cli, "_is_github_url", offline)
    monkeypatch.setattr(cli, "_sweep_body", offline)
    monkeypatch.setattr(spec, "load_spec", offline)
    argv = ["sweep", "--format", format, *selectors]
    if repo:
        argv += ["--repo", repo]

    result = CliRunner().invoke(cli.app, argv, color=force_color)

    assert result.exit_code == 2, result.output
    assert result.stdout == ""
    assert ("\x1b[" in result.stderr) == force_color
    stderr = unstyle(result.stderr)
    assert "--only" in stderr
    assert "unknown_fixture" in stderr


@pytest.mark.parametrize(
    "selectors,enabled_default,expected",
    [
        (["--only", "local_dev"], False, ["local_dev"]),
        (["--only", "publish_audit"], False, ["publish_audit"]),
        (
            ["--only", " local_dev, publish_audit ", "--only", "local_dev,, "],
            False,
            ["local_dev", "publish_audit"],
        ),
        ([], True, ["local_dev"]),
        (["--only", " , , "], True, ["local_dev"]),
    ],
)
def test_valid_selection_reaches_real_dispatch(
    monkeypatch, tmp_path, offline, selectors, enabled_default, expected
):
    calls = []

    def scan_local(root, **kwargs):
        assert root == tmp_path
        calls.append("local_dev")
        return [], {"repos_scanned": 0}

    def scan_publish(*, dev_root, **kwargs):
        assert dev_root == tmp_path
        calls.append("publish_audit")
        return {"summary": {"total_errors": 0}}, []

    def write_report(path, *args):
        assert path.parent == tmp_path

    monkeypatch.setattr(local_dev, "sweep_dev_repos", scan_local)
    monkeypatch.setattr(local_dev, "write_report", write_report)
    monkeypatch.setattr(publish_audit, "audit_publish", scan_publish)
    monkeypatch.setattr(publish_audit, "write_report", write_report)
    settings: dict[str, dict[str, object]] = {
        name: {"enabled": False} for name in spec.SweepSpec.model_fields
    }
    settings["local_dev"].update(enabled=enabled_default, output=str(tmp_path / "local.json"))
    settings["publish_audit"].update(dev_root=str(tmp_path), output=str(tmp_path / "publish.json"))
    source = tmp_path / "spec.yaml"
    source.write_text(json.dumps({"name": "fixture", "sweeps": settings}))

    result = CliRunner().invoke(
        cli.app,
        [
            "sweep",
            "--spec",
            str(source),
            "--dev-root",
            str(tmp_path),
            "--format",
            "json",
            *selectors,
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == expected
    assert sorted(json.loads(result.stdout)) == sorted(expected)
    assert result.stderr == ""
