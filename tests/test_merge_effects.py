import json
import subprocess

import pytest
from typer.testing import CliRunner

from devguard.cli import app
from devguard.merge_effects import _workflow, hypothetical_report, report


def workflow(events="push", run="vercel deploy --prod", condition=None):
    guard = f"    if: {condition}\n" if condition else ""
    return (
        f"on: {events}\njobs:\n  delivery:\n{guard}    runs-on: ubuntu-latest\n"
        f"    environment: production\n    steps:\n      - run: {run}\n"
    )


def git(repo, *args):
    return subprocess.check_output(["git", "-C", repo, *args], text=True).strip()


def commit(repo, message):
    git(repo, "add", ".")
    git(
        repo,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.org",
        "commit",
        "-qm",
        message,
    )
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repository(tmp_path):
    git(tmp_path, "init", "-qb", "trunk")
    f = tmp_path / ".github/workflows/delivery.yml"
    f.parent.mkdir(parents=True)
    f.write_text(workflow())
    base = commit(tmp_path, "configure production")
    (tmp_path / "app.py").write_text("x=1\n")
    head = commit(tmp_path, "code only")
    return tmp_path, f, base, head


def test_code_only_cli(repository):
    repo, f, base, head = repository
    cli = CliRunner().invoke(
        app,
        ["merge-effects", "--json", str(repo), "--base", base, "--head", head, "--branch", "trunk"],
    )
    assert cli.exit_code == 0, cli.output
    out = json.loads(cli.stdout)
    assert out["pr_changed_paths"] == ["app.py"]
    (e,) = out["effects"]
    assert (e["job"], e["event"], e["ref"], e["effect"], e["status"], e["line"]) == (
        "delivery",
        "push",
        "refs/heads/trunk",
        "production-deploy",
        "eligible",
        7,
    )
    assert "--prod" in f.read_text().splitlines()[e["line"] - 1]


@pytest.mark.parametrize(
    ("events", "command", "guard", "status", "kind"),
    [
        ("{push: {tags: ['v*']}}", "cargo publish", None, "excluded", "publish"),
        ("workflow_dispatch", "cargo publish", None, "excluded", "publish"),
        ("push", "cargo publish --dry-run", None, "eligible", "dry-run"),
        ("push", "vercel deploy", None, "eligible", "preview-deploy"),
        ("push", "vercel deploy --target production", None, "eligible", "production-deploy"),
        ("push", "vercel deploy --target custom", None, "eligible", "unresolved-deploy-target"),
        ("push", "npm publish && echo --dry-run", None, "eligible", "publish"),
        ("push", "./scripts/release.sh", None, "eligible", "unresolved-command"),
        (
            "push",
            "vercel deploy --prod",
            "github.event_name == 'pull_request'",
            "excluded",
            "production-deploy",
        ),
        ("push", "vercel deploy --prod", "inputs.ready", "uncertain", "production-deploy"),
        ("{push: {branches: ['stable']}}", "npm publish", None, "excluded", "publish"),
        ("{push: {paths: ['src/**', '!src/test/**']}}", "npm publish", None, "excluded", "publish"),
        ("{push: {paths-ignore: ['src/**']}}", "npm publish", None, "excluded", "publish"),
    ],
)
def test_dispositions(events, command, guard, status, kind):
    (e,) = _workflow(workflow(events, command, guard), "wf.yml", "trunk", ["src/test/file.rs"])
    assert (e["status"], e["effect"]) == (status, kind)


def test_unresolved_calls_and_hypotheticals(repository):
    repo, f, base, head = repository
    f.write_text(
        "on: {push: {paths: ['src/**']}}\njobs:\n  verify:\n    uses: ./.github/workflows/other.yml\n"
    )
    tip = commit(repo, "reusable")
    r = hypothetical_report(repo, tip, "trunk")
    (e,) = r["effects"]
    assert e["effect"] == "unresolved-reusable-workflow" and e["status"] == "uncertain"
    assert e["uncertainty"] and r["scenario"] == "hypothetical" and r["head"] is None
    assert (
        hypothetical_report(repo, tip, "trunk", ["src/lib.rs"])["effects"][0]["status"]
        == "eligible"
    )
    with pytest.raises(ValueError, match="identical"):
        report(repo, head, head, "trunk")


def test_changed_on_both_and_only_on_target(repository):
    repo, f, base, code = repository
    f.write_text(workflow(run="cargo publish --dry-run"))
    target = commit(repo, "change target workflow")
    git(repo, "checkout", "-q", "-b", "topic", base)
    (repo / "feature.py").touch()
    topic = commit(repo, "code only")
    assert report(repo, target, topic, "trunk")["effects"][0]["effect"] == "dry-run"
    f.write_text(workflow(run="npm publish"))
    changed = commit(repo, "change topic workflow")
    r = report(repo, target, changed, "trunk")
    assert r["status"] == "partial" and r["errors"] and not r["effects"]
    assert report(repo, base, changed, "trunk")["effects"][0]["destination"] == "npm"


def test_compound_shell_and_human_summary(repository):
    from devguard.merge_effects import _render

    text = workflow(run="cargo publish && cargo publish --dry-run")
    assert [e["effect"] for e in _workflow(text, "wf", "trunk", [])] == ["publish", "dry-run"]
    text = workflow(run='printf "%s" "literal && vercel deploy --prod" && vercel deploy')
    assert [e["effect"] for e in _workflow(text, "wf", "trunk", [])] == ["preview-deploy"]
    repo, _, base, head = repository
    r = report(repo, base, head, "trunk")
    assert "production-deploy (Vercel)" in _render(r)


@pytest.mark.parametrize(
    ("extra", "status"), [("", "excluded"), ("    if: always()\n", "eligible")]
)
def test_skipped_dependency(extra, status):
    wf = (
        "on: push\njobs:\n  gate:\n    if: false\n    runs-on: ubuntu-latest\n    steps: []\n  ship:\n    needs: gate\n"
        + extra
        + "    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish\n"
    )
    (e,) = _workflow(wf, "wf", "trunk", ["src/x"])
    assert e["status"] == status


@pytest.mark.parametrize(
    ("step_env", "command", "kind"),
    [
        ("", "npm publish", "dry-run"),
        ("", "npm publish --dry-run=false", "publish"),
        ("", "npm publish --no-dry-run", "publish"),
        ("", "npm publish --dry-run false", "publish"),
        ("", "npm publish --dry-run=true", "dry-run"),
        ("        env: {NPM_CONFIG_DRY_RUN: 'false'}\n", "npm publish", "publish"),
        (
            "        env: {NPM_CONFIG_DRY_RUN: '${{ vars.DRY_RUN }}'}\n",
            "npm publish",
            "unresolved-publish-mode",
        ),
    ],
)
def test_npm_publish_job_dry_run_with_step_overrides(step_env, command, kind):
    wf = (
        "on: {push: {branches: [trunk], paths: ['library/**']}}\n"
        "jobs:\n  pkg:\n    env: {NPM_CONFIG_DRY_RUN: 'true'}\n    runs-on: ubuntu-latest\n"
        f"    steps:\n      - run: {command}\n" + step_env
    )
    cases = [
        (wf, "trunk", ["library/index.js"], "eligible"),
        (wf, "release", ["library/index.js"], "excluded"),
        (wf, "trunk", ["docs/readme.md"], "excluded"),
        (
            wf.replace(
                "on: {push: {branches: [trunk], paths: ['library/**']}}", "on: pull_request"
            ),
            "trunk",
            ["library/index.js"],
            "excluded",
        ),
        (
            wf.replace(
                "      - run:", "      - if: github.event_name == 'pull_request'\n        run:"
            ),
            "trunk",
            ["library/index.js"],
            "excluded",
        ),
    ]
    for source, branch, changes, expected in cases:
        (effect,) = _workflow(source, "workflow.yml", branch, changes)
        assert (effect["effect"], effect["status"]) == (kind, expected)
