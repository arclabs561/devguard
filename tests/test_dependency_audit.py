"""Tests for the dependency_audit sweep."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from devguard.sweeps.dependency_audit import (
    DetectedEngine,
    _normalize_severity,
    audit_dependencies,
    detect_engines,
    parse_cargo_audit_json,
    parse_npm_audit_json,
    parse_pip_audit_json,
)

# ---------------------------------------------------------------------------
# JSON parser tests
# ---------------------------------------------------------------------------


class TestParseCargoAuditJson:
    def test_empty_input(self):
        with pytest.raises(ValueError):
            parse_cargo_audit_json("")

    def test_invalid_json(self):
        with pytest.raises(ValueError):
            parse_cargo_audit_json("not json")

    def test_no_vulnerabilities(self):
        data = json.dumps({"vulnerabilities": {"list": []}})
        assert parse_cargo_audit_json(data) == []

    def test_single_vuln(self):
        data = json.dumps(
            {
                "vulnerabilities": {
                    "list": [
                        {
                            "advisory": {
                                "id": "RUSTSEC-2024-0001",
                                "title": "Use after free in foo",
                                "severity": "high",
                                "cvss": None,
                            },
                            "package": {"name": "foo", "version": "1.0.0"},
                        }
                    ]
                }
            }
        )
        result = parse_cargo_audit_json(data)
        assert len(result) == 1
        assert result[0].id == "RUSTSEC-2024-0001"
        assert result[0].severity == "high"
        assert result[0].package == "foo"
        assert result[0].title == "Use after free in foo"

    def test_multiple_vulns(self):
        data = json.dumps(
            {
                "vulnerabilities": {
                    "list": [
                        {
                            "advisory": {
                                "id": "RUSTSEC-0001",
                                "title": "a",
                                "severity": "critical",
                            },
                            "package": {"name": "bar"},
                        },
                        {
                            "advisory": {"id": "RUSTSEC-0002", "title": "b", "severity": "low"},
                            "package": {"name": "baz"},
                        },
                    ]
                }
            }
        )
        result = parse_cargo_audit_json(data)
        assert len(result) == 2
        assert result[0].severity == "critical"
        assert result[1].severity == "low"


class TestParseNpmAuditJson:
    def test_empty_input(self):
        with pytest.raises(ValueError):
            parse_npm_audit_json("")

    def test_invalid_json(self):
        with pytest.raises(ValueError):
            parse_npm_audit_json("{broken")

    def test_no_vulnerabilities(self):
        data = json.dumps({"vulnerabilities": {}})
        assert parse_npm_audit_json(data) == []

    def test_single_vuln(self):
        data = json.dumps(
            {
                "vulnerabilities": {
                    "lodash": {
                        "name": "lodash",
                        "severity": "high",
                        "title": "Prototype pollution",
                        "fixAvailable": {"name": "lodash", "version": "4.17.21"},
                    }
                }
            }
        )
        result = parse_npm_audit_json(data)
        assert len(result) == 1
        assert result[0].package == "lodash"
        assert result[0].severity == "high"

    def test_moderate_maps_to_medium(self):
        data = json.dumps(
            {
                "vulnerabilities": {
                    "express": {
                        "name": "express",
                        "severity": "moderate",
                        "title": "Open redirect",
                    }
                }
            }
        )
        result = parse_npm_audit_json(data)
        assert result[0].severity == "medium"


class TestParsePipAuditJson:
    def test_empty_input(self):
        with pytest.raises(ValueError):
            parse_pip_audit_json("")

    def test_invalid_json(self):
        with pytest.raises(ValueError):
            parse_pip_audit_json("nope")

    def test_no_vulns(self):
        data = json.dumps([{"name": "requests", "version": "2.31.0", "vulns": []}])
        assert parse_pip_audit_json(data) == []

    def test_single_vuln(self):
        data = json.dumps(
            [
                {
                    "name": "urllib3",
                    "version": "1.26.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2023-001",
                            "description": "Request smuggling via CRLF",
                            "severity": "high",
                            "fix_versions": ["1.26.18"],
                            "aliases": [],
                        }
                    ],
                }
            ]
        )
        result = parse_pip_audit_json(data)
        assert len(result) == 1
        assert result[0].id == "PYSEC-2023-001"
        assert result[0].package == "urllib3"
        assert result[0].severity == "high"


class TestNormalizeSeverity:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("critical", "critical"),
            ("HIGH", "high"),
            ("Medium", "medium"),
            ("low", "low"),
            ("moderate", "medium"),
            ("informational", "low"),
            ("info", "low"),
            ("none", "low"),
            ("negligible", "low"),
            ("", "unknown"),
            (None, "unknown"),
            ("banana", "unknown"),
        ],
    )
    def test_mapping(self, raw, expected):
        assert _normalize_severity(raw) == expected


# ---------------------------------------------------------------------------
# Repo discovery and language detection
# ---------------------------------------------------------------------------


class TestDetectEngines:
    def test_rust_repo(self, tmp_path: Path):
        (tmp_path / "Cargo.lock").touch()
        engines = detect_engines(tmp_path)
        assert len(engines) == 1
        assert engines[0] == DetectedEngine(language="rust", engine="cargo-audit")

    def test_js_repo_npm(self, tmp_path: Path):
        (tmp_path / "package-lock.json").touch()
        engines = detect_engines(tmp_path)
        assert len(engines) == 1
        assert engines[0].engine == "npm-audit"

    def test_js_repo_yarn(self, tmp_path: Path):
        (tmp_path / "yarn.lock").touch()
        engines = detect_engines(tmp_path)
        assert len(engines) == 1
        assert engines[0].engine == "npm-audit"

    def test_python_repo_uv(self, tmp_path: Path):
        (tmp_path / "uv.lock").touch()
        engines = detect_engines(tmp_path)
        assert len(engines) == 1
        assert engines[0].engine == "pip-audit"

    def test_python_repo_requirements(self, tmp_path: Path):
        (tmp_path / "requirements.txt").touch()
        engines = detect_engines(tmp_path)
        assert len(engines) == 1
        assert engines[0].engine == "pip-audit"

    def test_multi_language(self, tmp_path: Path):
        (tmp_path / "Cargo.lock").touch()
        (tmp_path / "package-lock.json").touch()
        engines = detect_engines(tmp_path)
        engine_names = {e.engine for e in engines}
        assert "cargo-audit" in engine_names
        assert "npm-audit" in engine_names

    def test_no_manifests(self, tmp_path: Path):
        (tmp_path / "README.md").touch()
        engines = detect_engines(tmp_path)
        assert engines == []

    def test_deduplicates_engines(self, tmp_path: Path):
        """Multiple JS lockfiles should produce only one npm-audit entry."""
        (tmp_path / "package-lock.json").touch()
        (tmp_path / "yarn.lock").touch()
        engines = detect_engines(tmp_path)
        assert len(engines) == 1
        assert engines[0].engine == "npm-audit"


class TestRepoDiscovery:
    def test_discovers_git_repos(self, tmp_path: Path):
        repo_a = tmp_path / "repo-a"
        repo_a.mkdir()
        (repo_a / ".git").mkdir()
        (repo_a / "Cargo.lock").touch()

        repo_b = tmp_path / "repo-b"
        repo_b.mkdir()
        (repo_b / ".git").mkdir()
        (repo_b / "package-lock.json").touch()

        from devguard.sweeps._common import iter_git_repos as _iter_git_repos

        repos = _iter_git_repos(tmp_path, max_depth=2)
        repo_names = {r.name for r in repos}
        assert "repo-a" in repo_names
        assert "repo-b" in repo_names


# ---------------------------------------------------------------------------
# Graceful tool-not-found handling
# ---------------------------------------------------------------------------


class TestGracefulSkip:
    def test_skips_when_tool_not_installed(self, tmp_path: Path):
        """When audit tools are not on PATH, repos should be skipped gracefully."""
        repo = tmp_path / "myrepo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / "Cargo.lock").touch()

        with patch("devguard.sweeps.dependency_audit.shutil.which", return_value=None):
            report, errors = audit_dependencies(
                dev_root=tmp_path,
                max_depth=2,
                engines=["cargo-audit"],
            )

        assert report["summary"]["total_vulns"] == 0
        assert len(errors) == 0
        # The repo should appear with a skipped engine
        repo_entries = [r for r in report["repos"] if "myrepo" in r["repo_path"]]
        assert len(repo_entries) == 1
        assert any("not installed" in s for s in repo_entries[0]["skipped_engines"])

    def test_empty_dev_root(self, tmp_path: Path):
        """No repos found should produce a clean empty report."""
        report, errors = audit_dependencies(dev_root=tmp_path, max_depth=2)
        assert report["summary"]["total_vulns"] == 0
        assert report["summary"]["repos_with_vulns"] == 0
        assert errors == []

    def test_exclude_globs(self, tmp_path: Path):
        """Excluded repos should not appear in results."""
        repo = tmp_path / "_forks" / "forked"
        repo.mkdir(parents=True)
        (repo / ".git").mkdir()
        (repo / "Cargo.lock").touch()

        report, errors = audit_dependencies(
            dev_root=tmp_path,
            max_depth=3,
            exclude_repo_globs=["*/_forks/*"],
        )
        repo_paths = [r["repo_path"] for r in report["repos"]]
        assert not any("forked" in p for p in repo_paths)


# Shapes follow cargo-audit's vulnerabilities.list, npm v7+ vulnerabilities,
# and pip-audit's JSON formatter (dependencies/fixes, or the legacy list).
@pytest.mark.parametrize(
    "engine,manifest,clean,finding",
    [
        (
            "cargo-audit",
            "Cargo.lock",
            {"vulnerabilities": {"list": []}},
            {
                "vulnerabilities": {
                    "list": [
                        {
                            "advisory": {"id": "RUSTSEC-TEST", "title": "test"},
                            "package": {"name": "demo"},
                        }
                    ]
                }
            },
        ),
        (
            "npm-audit",
            "package-lock.json",
            {"vulnerabilities": {}},
            {"vulnerabilities": {"demo": {"severity": "high", "via": [{"title": "test"}]}}},
        ),
        (
            "pip-audit",
            "requirements.txt",
            {"dependencies": [], "fixes": []},
            {
                "dependencies": [
                    {
                        "name": "demo",
                        "version": "1.0",
                        "vulns": [{"id": "PYSEC-TEST", "description": "test"}],
                    }
                ],
                "fixes": [],
            },
        ),
    ],
)
@pytest.mark.parametrize(
    "outcome",
    [
        "clean",
        "finding",
        "malformed",
        "schema",
        "envelope",
        "unexpected",
        "empty_failure",
        "timeout",
        "exception",
    ],
)
def test_real_audit_result_boundary(tmp_path, engine, manifest, clean, finding, outcome):
    repo = tmp_path / "project"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / manifest).write_text("demo==1.0\n")
    secret = "private-output-must-not-escape"
    body, code = clean, 0
    if outcome == "finding":
        body, code = finding, 1
    elif outcome == "schema":
        body = {"vulnerabilities": [], "dependencies": {}, "fixes": []}
    elif outcome == "envelope":
        body = {"error": secret}
    elif outcome == "unexpected":
        code = 7
    elif outcome == "empty_failure":
        code = 1
    raw = secret if outcome == "malformed" else json.dumps(body)
    with (
        patch("devguard.sweeps.dependency_audit.shutil.which", return_value="audit-tool"),
        patch("devguard.sweeps.dependency_audit.subprocess.run") as run,
    ):
        if outcome == "timeout":
            run.side_effect = subprocess.TimeoutExpired(secret, 1, output=secret)
        elif outcome == "exception":
            run.side_effect = OSError(secret)
        else:
            run.return_value = subprocess.CompletedProcess([], code, stdout=raw, stderr=secret)
        report, errors = audit_dependencies(dev_root=tmp_path, engines=[engine])
    assert run.call_args.kwargs["cwd"] == str(repo)
    if engine == "pip-audit":
        assert run.call_args.args[0] == [
            "pip-audit",
            "--format=json",
            "--output=-",
            "--no-deps",
            "--disable-pip",
            "--strict",
            "-r",
            "requirements.txt",
        ]
    assert secret not in json.dumps(report)
    entry = report["repos"][0]
    if outcome in ("clean", "finding"):
        assert errors == []
        assert entry["engines_run"] == [engine]
        assert report["summary"]["total_vulns"] == (1 if outcome == "finding" else 0)
    else:
        assert errors
        assert entry["error"]
        assert entry["engines_run"] == []


@pytest.mark.parametrize("manifest", ["uv.lock", "poetry.lock"])
def test_python_lock_only_is_unsupported_not_host_audit(tmp_path, manifest):
    (tmp_path / ".git").mkdir()
    (tmp_path / manifest).touch()
    with (
        patch("devguard.sweeps.dependency_audit.shutil.which", return_value="pip-audit"),
        patch("devguard.sweeps.dependency_audit.subprocess.run") as run,
    ):
        report, errors = audit_dependencies(dev_root=tmp_path)
    run.assert_not_called()
    assert "unsupported input" in errors[0]
    assert report["repos"][0]["engines_run"] == []


@pytest.mark.parametrize(
    "payload",
    [
        {"dependencies": [{"name": "demo", "skip_reason": "private detail"}], "fixes": []},
        {"dependencies": [{"name": "demo", "version": "1", "vulns": None}], "fixes": []},
        {"dependencies": [], "fixes": "invalid"},
        [None],
    ],
)
def test_incomplete_pip_results_are_not_clean(payload):
    with pytest.raises(ValueError):
        parse_pip_audit_json(json.dumps(payload))


def test_skipped_pip_dependency_is_a_sanitized_report_error(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "requirements.txt").write_text("demo==1.0\n")
    raw = json.dumps(
        {"dependencies": [{"name": "demo", "skip_reason": "private-skip-detail"}], "fixes": []}
    )
    with (
        patch("devguard.sweeps.dependency_audit.shutil.which", return_value="pip-audit"),
        patch(
            "devguard.sweeps.dependency_audit.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, stdout=raw),
        ),
    ):
        report, errors = audit_dependencies(dev_root=tmp_path, engines=["pip-audit"])
    assert errors
    assert report["repos"][0]["engines_run"] == []
    assert "private-skip-detail" not in json.dumps(report)
