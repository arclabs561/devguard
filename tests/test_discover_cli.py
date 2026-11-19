"""Discover's JSON mode is one lossless stdout document, with diagnostics separate."""

import json
import socket
import subprocess
from unittest.mock import AsyncMock, Mock

import pytest
from pydantic_settings import BaseSettings
from typer.testing import CliRunner

from devguard import cli, config, discovery


@pytest.fixture
def offline_discovery(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("discovery CLI test crossed its offline boundary")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(BaseSettings, "__init__", forbidden)
    monkeypatch.setattr(config, "get_settings", forbidden)
    monkeypatch.setattr(cli, "get_settings", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    result = discovery.DiscoveryResult()
    result.add_resource("npm", "[bold]literal[/bold] café 雪 " + "x" * 300)
    result.errors.append("[red]literal error[/red] Ω " + "e" * 300)
    result.metadata["detail"] = "Unicode 雪 and [link=https://example.invalid]markup[/link]"
    calls = []

    async def discover_spy(spec, base):
        calls.append((spec.name, base))
        return result

    monkeypatch.setattr(discovery, "discover_all", discover_spy)
    return result, calls


@pytest.mark.parametrize("existing_spec", [True, False])
def test_discover_json_is_lossless_document(tmp_path, offline_discovery, existing_spec):
    expected, calls = offline_discovery
    spec = tmp_path / "spec.yaml"
    if existing_spec:
        spec.write_text("name: offline-fixture\ndiscovery_rules: []\n")

    result = CliRunner().invoke(
        cli.app, ["discover", "--spec", str(spec), "--base-path", str(tmp_path), "--json"]
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == expected.to_dict()
    assert len(calls) == 1
    assert calls[0][1] == tmp_path
    assert "Discovering resources from:" in result.stderr
    assert "Using spec:" in result.stderr
    if not existing_spec:
        assert "Spec file not found:" in result.stderr
        assert "Using default spec..." in result.stderr


def test_discover_json_invalid_spec_keeps_stdout_empty(tmp_path, offline_discovery):
    _, calls = offline_discovery
    spec = tmp_path / "invalid.yaml"
    spec.write_text("name: [unterminated\n")

    result = CliRunner().invoke(
        cli.app, ["discover", "--spec", str(spec), "--base-path", str(tmp_path), "--json"]
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "Error loading spec:" in result.stderr
    assert calls == []


def test_discover_human_output_stays_on_stdout(tmp_path, offline_discovery):
    _, calls = offline_discovery
    result = CliRunner().invoke(
        cli.app,
        ["discover", "--spec", str(tmp_path / "missing.yaml"), "--base-path", str(tmp_path)],
    )

    assert result.exit_code == 0, result.output
    assert result.stderr == ""
    for label in (
        "Spec file not found:",
        "Using default spec...",
        "Discovering resources from:",
        "Discovery Results",
        "Discovered Resources",
        "Errors:",
    ):
        assert label in result.stdout
    assert len(calls) == 1


@pytest.mark.parametrize("json_output", [False, True])
def test_discover_persists_all_owned_repos_and_manual_resources(tmp_path, monkeypatch, json_output):
    from devguard.spec import MonitorSpec, get_default_spec

    rule = next(r for r in get_default_spec().discovery_rules if r.name == "github_repos")
    repos = [f"owner/repo-{i:03}" for i in range(122)]
    manual = "other-owner/external"
    expected = [*repos, manual]

    process = Mock(
        returncode=0, communicate=AsyncMock(return_value=("\n".join(repos).encode(), b""))
    )
    gh = AsyncMock(return_value=process)
    monkeypatch.setattr(discovery.asyncio, "create_subprocess_exec", gh)
    spec = MonitorSpec(
        name="owned-repos",
        discovery_rules=[rule],
        manual_resources={"github": [repos[0], manual]},
    )
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(spec.model_dump_json())
    env_path = tmp_path / ".env"
    env_path.write_text("OTHER=untouched\nGITHUB_REPOS_TO_MONITOR=old/repo\n")
    args = ["discover", "--spec", str(spec_path), "--update-env", "--env-file", str(env_path)]
    if json_output:
        args.append("--json")
    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == 0, result.output
    assert gh.await_args.args == (
        "gh",
        "api",
        "--paginate",
        "user/repos?affiliation=owner&per_page=100",
        "--jq",
        ".[].full_name",
    )
    assert env_path.read_text().splitlines()[:2] == [
        "OTHER=untouched",
        "GITHUB_REPOS_TO_MONITOR=" + ",".join(expected),
    ]
    if json_output:
        assert json.loads(result.stdout)["resources"]["github"] == expected
        assert "Updated .env file" in result.stderr
