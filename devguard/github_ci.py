"""Report the checks GitHub associates with each owned repository's default-branch head."""

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

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


def _branch_protection(row: dict) -> str:
    if row["branch"] is None:
        return "NO_BRANCH" if row["state"] == "EMPTY" else "UNKNOWN"
    branch = quote(row["branch"], safe="")
    endpoint = f"repos/{row['repo']}/branches/{branch}"
    try:
        result = subprocess.run(
            ["gh", "api", endpoint, "--jq", ".protected"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "UNKNOWN"
    if result.returncode:
        return "UNKNOWN"
    return {"true": "PROTECTED", "false": "UNPROTECTED"}.get(result.stdout.strip(), "UNKNOWN")


def github_ci(
    json_output: bool = typer.Option(False, "--json", help="Print one JSON report."),
    branch_protection: bool = typer.Option(
        False,
        "--branch-protection",
        help="Read the default branch's protection flag for each repository.",
    ),
    fail_on_red: bool = typer.Option(False, "--fail-on-red", help="Exit 1 for FAILURE or ERROR."),
) -> None:
    """Report default-branch checks across the authenticated user's owned repositories."""
    try:
        report = owned_repo_checks()
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        typer.echo(f"Could not read the GitHub portfolio: {exc}", err=True)
        raise typer.Exit(2) from exc

    rows = report["repositories"]
    if branch_protection:
        with ThreadPoolExecutor(max_workers=4) as pool:
            for row, protection in zip(rows, pool.map(_branch_protection, rows), strict=True):
                row["branch_protection"] = protection

    if json_output:
        typer.echo(json.dumps(report, ensure_ascii=False))
    else:
        table = Table(title=f"{report['owner']} · default-branch checks")
        for label in ("Repository", "Branch", "Checks"):
            table.add_column(label)
        if branch_protection:
            table.add_column("Protection")
        for row in rows:
            name = row["repo"] + (" (archived)" if row["archived"] else "")
            cells = [name, row["branch"] or "—", row["state"]]
            if branch_protection:
                cells.append(row["branch_protection"])
            table.add_row(*cells)
        Console().print(table)

    if branch_protection and any(r["branch_protection"] == "UNKNOWN" for r in rows):
        raise typer.Exit(2)
    if fail_on_red and any(r["state"] in {"FAILURE", "ERROR"} for r in report["repositories"]):
        raise typer.Exit(1)
