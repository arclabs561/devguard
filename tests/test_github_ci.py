import json
import subprocess

import pytest
from typer.testing import CliRunner

from devguard.cli import app
from devguard.github_ci import _QUERY


def repo(number, state="SUCCESS"):
    return {
        "nameWithOwner": f"reader/r{number}",
        "visibility": "PRIVATE" if number % 2 else "PUBLIC",
        "isArchived": number == 5,
        "isFork": number == 6,
        "isEmpty": False,
        "defaultBranchRef": {
            "name": "trunk",
            "target": {
                "oid": f"{number:040x}",
                "url": f"https://example.org/r{number}/commit",
                "statusCheckRollup": {"state": state} if state else None,
            },
        },
    }


def page(nodes, cursor=None):
    return {
        "data": {
            "viewer": {
                "login": "reader",
                "repositories": {
                    "nodes": nodes,
                    "pageInfo": {"hasNextPage": cursor is not None, "endCursor": cursor},
                },
            }
        }
    }


def use_pages(monkeypatch, *pages):
    responses = iter(pages)
    calls = []

    def gh(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, json.dumps(next(responses)), "")

    monkeypatch.setattr("devguard.github_ci.subprocess.run", gh)
    return calls


def test_full_owned_inventory(monkeypatch):
    first = [repo(i) for i in range(100)]
    last = [repo(i) for i in range(100, 122)]
    last[2] = repo(102, "FAILURE")
    last[3] = repo(103, None)
    last[4].update(defaultBranchRef=None, isEmpty=True)
    last[5].update(defaultBranchRef=None)
    calls = use_pages(monkeypatch, page(first, "next"), page(last))
    result = CliRunner().invoke(app, ["github-ci", "--json", "--fail-on-red"])
    assert result.exit_code == 1, result.output
    report = json.loads(result.stdout)
    rows = report["repositories"]
    assert report["owner"] == "reader"
    assert len(rows) == 122
    assert rows[5]["archived"] and rows[6]["fork"]
    assert rows[101]["visibility"] == "PRIVATE"
    assert [r["state"] for r in rows[102:106]] == [
        "FAILURE",
        "NO_REPORTED_CHECKS",
        "EMPTY",
        "UNKNOWN",
    ]
    assert rows[101]["branch"] == "trunk" and rows[101]["sha"] == f"{101:040x}"
    assert rows[104]["sha"] is None
    assert calls[1] == [*calls[0], "-f", "cursor=next"]
    assert "ownerAffiliations: [OWNER]" in _QUERY


@pytest.mark.parametrize("state", ["PENDING", "EXPECTED", "SUCCESS", None])
def test_incomplete_or_green_checks_do_not_trip_fail_on_red(monkeypatch, state):
    use_pages(monkeypatch, page([repo(1, state)]))
    result = CliRunner().invoke(app, ["github-ci", "--fail-on-red"])
    assert result.exit_code == 0 and (state or "NO_REPORTED_CHECKS") in result.stdout


def test_partial_page_fails_without_emitting_partial_report(monkeypatch):
    use_pages(monkeypatch, page([repo(1)], "next"), {"errors": [{"message": "forbidden"}]})
    result = CliRunner().invoke(app, ["github-ci", "--json"])
    assert result.exit_code == 2 and result.stdout == "" and "forbidden" in result.stderr


def test_empty_account(monkeypatch):
    use_pages(monkeypatch, page([]))
    result = CliRunner().invoke(app, ["github-ci", "--json"])
    assert result.exit_code == 0 and json.loads(result.stdout)["repositories"] == []
