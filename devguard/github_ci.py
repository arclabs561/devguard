"""Report the checks GitHub associates with each owned repository's default-branch head."""

import json
import subprocess

import typer
from rich.console import Console
from rich.table import Table

_QUERY = """
query($cursor: String) {
  viewer {
    login
    repositories(first: 100, after: $cursor, ownerAffiliations: [OWNER],
                 orderBy: {field: NAME, direction: ASC}) {
      nodes {
        nameWithOwner visibility isArchived isFork isEmpty
        defaultBranchRef {
          name
          target { ... on Commit { oid url statusCheckRollup { state } } }
        }
      }
      pageInfo { hasNextPage endCursor }
    }
  }
}
"""


def owned_repo_checks() -> dict:
    """Read all pages through the authenticated GitHub CLI without cloning repositories."""
    rows = []
    cursor = None
    seen_cursors = set()
    while True:
        args = ["gh", "api", "graphql", "-f", f"query={_QUERY}"]
        if cursor is not None:
            args.extend(["-f", f"cursor={cursor}"])
        page = subprocess.run(args, capture_output=True, text=True, timeout=60)
        if page.returncode:
            raise ValueError(page.stderr.strip() or "GitHub query failed")
        payload = json.loads(page.stdout)
        if payload.get("errors"):
            raise ValueError("GitHub returned an incomplete result: " + str(payload["errors"]))
        viewer = payload["data"]["viewer"]
        repos = viewer["repositories"]
        for repo in repos["nodes"]:
            branch = repo["defaultBranchRef"]
            commit = branch["target"] if branch else None
            rollup = commit.get("statusCheckRollup") if commit else None
            if repo["isEmpty"]:
                state = "EMPTY"
            elif not commit or "oid" not in commit:
                state = "UNKNOWN"
            elif rollup is None:
                state = "NO_REPORTED_CHECKS"
            else:
                state = rollup["state"]
            rows.append(
                {
                    "repo": repo["nameWithOwner"],
                    "visibility": repo["visibility"],
                    "archived": repo["isArchived"],
                    "fork": repo["isFork"],
                    "branch": branch["name"] if branch else None,
                    "state": state,
                    "sha": commit.get("oid") if commit else None,
                    "commit_url": commit.get("url") if commit else None,
                }
            )
        info = repos["pageInfo"]
        if not info["hasNextPage"]:
            return {"owner": viewer["login"], "repositories": rows}
        cursor = info["endCursor"]
        if not cursor or cursor in seen_cursors:
            raise ValueError("GitHub returned an invalid pagination cursor")
        seen_cursors.add(cursor)


def github_ci(
    json_output: bool = typer.Option(False, "--json", help="Print one JSON report."),
    fail_on_red: bool = typer.Option(False, "--fail-on-red", help="Exit 1 for FAILURE or ERROR."),
) -> None:
    """Report default-branch checks across the authenticated user's owned repositories."""
    try:
        report = owned_repo_checks()
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        typer.echo(f"Could not read the GitHub portfolio: {exc}", err=True)
        raise typer.Exit(2) from exc

    if json_output:
        typer.echo(json.dumps(report, ensure_ascii=False))
    else:
        table = Table(title=f"{report['owner']} · default-branch checks")
        for label in ("Repository", "Branch", "Checks"):
            table.add_column(label)
        for row in report["repositories"]:
            name = row["repo"] + (" (archived)" if row["archived"] else "")
            table.add_row(name, row["branch"] or "—", row["state"])
        Console().print(table)

    if fail_on_red and any(r["state"] in {"FAILURE", "ERROR"} for r in report["repositories"]):
        raise typer.Exit(1)
