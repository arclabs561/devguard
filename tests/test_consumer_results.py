import json

import pytest
from typer.testing import CliRunner

from devguard.cli import app

BASE, HEAD = "a" * 40, "b" * 40


def obs(revision, outcome="pass", **fields):
    return {
        "revision": revision,
        "outcome": outcome,
        "exit_code": 0,
        "evidence": "logs/run",
        **fields,
    }


def run_case(tmp_path, base, head, *, repository="org/sample", compare=True, **extra):
    case = {
        "fixture": "public-reader",
        "assertion": "consumer reads old output",
        "tool": "reader 2.0",
        "head": head,
        **extra,
    }
    if base is not None:
        case["base"] = base
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps({"schema_version": 1, "repository": "org/sample", "cases": [case]}))
    args = ["consumer-results", str(path), "--repository", repository, "--head", HEAD]
    if compare:
        args += ["--base", BASE]
    result = CliRunner().invoke(app, args)
    return result.exit_code, json.loads(result.stdout)


@pytest.mark.parametrize(
    ("base", "head", "decision", "status"),
    [
        (obs(BASE), obs(HEAD), "pass", 0),
        (obs(BASE), obs(HEAD, "fail"), "regression", 1),
        (obs(BASE, "fail"), obs(HEAD), "inconclusive", 3),
        (obs(BASE), obs(HEAD, "skip", reason="browser unavailable"), "inconclusive", 3),
        (obs(BASE, "error", reason="tool not installed"), obs(HEAD), "inconclusive", 3),
        (obs(HEAD), obs(HEAD), "inconclusive", 3),
        (obs(BASE), obs(BASE), "inconclusive", 3),
        (None, obs(HEAD), "inconclusive", 3),
    ],
)
def test_compares_exact_revisions_and_actual_outcomes(tmp_path, base, head, decision, status):
    rc, report = run_case(tmp_path, base, head)
    assert rc == status
    assert report["cases"][0]["decision"] == decision
    if head["outcome"] == "skip":
        assert "browser unavailable" in report["cases"][0]["reason"]


def test_keeps_raw_exit_code_and_packaged_artifact_without_opening_it(tmp_path):
    # A runner can exit zero even when a consumer assertion fails.
    marker = tmp_path / "unwanted"
    artifact = {
        "package": "image-writer",
        "version": "2.0",
        "registry": "internal",
        "sha256": "c" * 64,
    }
    head = obs(HEAD, "fail", artifact=artifact, evidence="https://invalid.example/artifact")
    rc, report = run_case(tmp_path, None, head, compare=False, command=f"touch {marker}")
    assert rc == 1
    result = report["cases"][0]
    assert result["decision"] == "observed_fail"
    assert result["head"] == head
    assert not marker.exists()


def test_scope_mismatch_or_unpinned_base_is_inconclusive(tmp_path):
    rc, report = run_case(tmp_path, obs(BASE), obs(HEAD), repository="org/other")
    assert rc == 3 and "repository" in report["cases"][0]["reason"]
    rc, report = run_case(tmp_path, obs(BASE), obs(HEAD), compare=False)
    assert rc == 3 and "expected base" in report["cases"][0]["reason"]
    rc, report = run_case(tmp_path, None, obs(HEAD), compare=False)
    assert rc == 0 and report["cases"][0]["decision"] == "observed_pass"


@pytest.mark.parametrize(
    "bad",
    [
        obs("main"),
        obs(HEAD, "skip"),
        obs(HEAD, "error"),
        obs(HEAD, exit_code=True),
        obs(HEAD, artifact={"sha256": "bad"}),
    ],
)
def test_invalid_observation_fails_closed(tmp_path, bad):
    rc, report = run_case(tmp_path, obs(BASE), bad)
    assert rc == 3 and report["errors"]


def test_versions_duplicates_and_empty_report_are_rejected(tmp_path):
    path = tmp_path / "input.json"
    case = {"fixture": "f", "assertion": "a", "tool": "t1", "head": obs(HEAD)}
    for version, cases in ((2, [case]), (True, [case]), (1, []), (1, [case, case])):
        path.write_text(
            json.dumps({"schema_version": version, "repository": "org/sample", "cases": cases})
        )
        result = CliRunner().invoke(
            app, ["consumer-results", str(path), "--repository", "org/sample", "--head", HEAD]
        )
        assert result.exit_code == 3 and json.loads(result.stdout)["errors"]


def test_recorded_command_and_nonzero_exit_are_data(tmp_path):
    mark = tmp_path / "marker"
    head = obs(HEAD, "pass", exit_code=17, command=["touch", str(mark)])
    rc, report = run_case(tmp_path, obs(BASE), head)
    assert rc == 0 and report["cases"][0]["head"]["command"] == ["touch", str(mark)]
    assert not mark.exists()


def test_artifact_identity_and_identical_revisions_cannot_imply_regression(tmp_path):
    original = {"package": "writer", "version": "1.0", "registry": "internal", "sha256": "a" * 64}
    new = {**original, "version": "2.0", "sha256": "b" * 64}
    for artifact, decision in (
        (new, "regression"),
        ({**new, "package": "other"}, "inconclusive"),
        ({**new, "registry": "other"}, "inconclusive"),
    ):
        _, report = run_case(
            tmp_path, obs(BASE, artifact=original), obs(HEAD, "fail", artifact=artifact)
        )
        assert report["cases"][0]["decision"] == decision
    _, report = run_case(tmp_path, obs(HEAD), obs(HEAD, "fail"))
    path = tmp_path / "evidence.json"
    rc = CliRunner().invoke(
        app,
        [
            "consumer-results",
            str(path),
            "--repository",
            "org/sample",
            "--head",
            HEAD,
            "--base",
            HEAD,
        ],
    )
    assert rc.exit_code == 3 and "same revision" in rc.stdout
