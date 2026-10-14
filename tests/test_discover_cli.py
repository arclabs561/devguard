"""Discover's JSON mode is one lossless stdout document, with diagnostics separate."""

import json
import socket
import subprocess

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
