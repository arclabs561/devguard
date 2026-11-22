"""`devguard fleet` and `devguard cache`: many-repository sweeps and their cache."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from devguard import fleet as fl

_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
    "unknown": "yellow",
}


def _human_bytes(count: int) -> str:
    size = float(count)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def _select_sweeps(only: list[str] | None) -> list[str]:
    from devguard.spec import SweepSpec

    wanted = [s.strip() for w in (only or []) for s in w.split(",") if s.strip()]
    unknown = sorted(set(wanted) - SweepSpec.model_fields.keys())
    if unknown:
        raise typer.BadParameter(f"Unknown sweep names: {', '.join(unknown)}", param_hint="--only")
    return sorted(set(wanted)) or list(fl.REPO_SCOPED_SWEEPS)


def _collect_refs(
    targets: list[str] | None,
    owner: list[str] | None,
    mine: bool,
    root_dir: str | None,
    repos_file: str | None,
    max_depth: int,
) -> list[fl.RepoRef]:
    refs: list[fl.RepoRef] = []
    names = list(targets or [])
    if repos_file:
        text = sys.stdin.read() if repos_file == "-" else Path(repos_file).read_text()
        names += [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    for name in names:
        refs.append(fl.parse_target(name))
    if mine:
        refs += fl.list_owner_repos(None)
    for login in owner or []:
        refs += fl.list_owner_repos(login)
    if root_dir:
        from devguard.sweeps._common import iter_git_repos

        base = Path(root_dir).expanduser()
        if not base.is_dir():
            raise ValueError(f"{root_dir}: not a directory")
        for checkout in sorted(iter_git_repos(base, max_depth)):
            path = checkout.resolve()
            refs.append(fl.RepoRef(name=path.name, path=path))
    return refs


def _emit_json(data: list | dict, *, stdout: bool, output: str | None) -> None:
    if stdout or output:
        payload = json.dumps(data, indent=2) + "\n"
        if output:
            out_path = Path(output).expanduser()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(payload, encoding="utf-8")
        if stdout:
            sys.stdout.write(payload)


def _counts_cells(counts: dict[str, int]) -> list[str]:
    return [
        f"[{_STYLE[s]}]{counts[s]}[/{_STYLE[s]}]" if counts[s] else "[dim]·[/dim]"
        for s in fl.SEVERITIES
    ]


def _print_text(
    console: Console,
    report: dict,
    results: list[fl.RepoResult],
    details: str,
    top: int,
    min_severity: str,
) -> None:
    owners = {r.name.split("/", 1)[0] for r in results if r.url and "/" in r.name}
    strip = f"{next(iter(owners))}/" if len(owners) == 1 else ""
    table = Table(title="Repositories", title_justify="left", show_edge=False, pad_edge=False)
    table.add_column("repo", no_wrap=True, min_width=12)
    for sev in fl.SEVERITIES:
        table.add_column(sev[:4], justify="right", no_wrap=True)
    table.add_column("state", no_wrap=True)
    table.add_column("worst finding", overflow="ellipsis", no_wrap=True)
    ordered = sorted(
        results,
        key=lambda r: (r.status != "error", r.worst, [-c for c in r.counts.values()], r.name),
    )
    unlisted = 0
    for res in ordered:
        notable = any(fl.severity_at_least(f["severity"], min_severity) for f in res.findings)
        if res.status != "error" and res.exit_code != 3 and not notable:
            unlisted += 1
            continue
        state = res.status
        if res.status == "error":
            state = "[bold red]error[/bold red]"
        elif res.exit_code == 3:
            state += " [yellow](partial)[/yellow]"
        if res.status == "error":
            note = escape(res.errors[0]) if res.errors else ""
        elif res.findings:
            first = res.findings[0]
            note = escape(f"{first['sweep']}/{first['check']}")
        else:
            note = "—"
        table.add_row(escape(res.name.removeprefix(strip)), *_counts_cells(res.counts), state, note)
    if table.row_count:
        if strip:
            table.title = f"Repositories ({strip.rstrip('/')})"
        console.print(table)
    if unlisted:
        console.print(
            f"[dim]{unlisted} repositories with nothing at {min_severity} or worse not listed "
            "(--min-severity info lists all).[/dim]",
            highlight=False,
        )

    if report["checks"]:
        checks = Table(
            title="Most frequent checks", title_justify="left", show_edge=False, pad_edge=False
        )
        checks.add_column("severity")
        checks.add_column("sweep")
        checks.add_column("check")
        checks.add_column("count", justify="right")
        rows = [r for r in report["checks"] if fl.severity_at_least(r["severity"], min_severity)]
        for row in rows[:top]:
            sev = row["severity"]
            checks.add_row(
                f"[{_STYLE[sev]}]{sev}[/{_STYLE[sev]}]",
                row["sweep"],
                escape(row["check"]),
                str(row["count"]),
            )
        console.print()
        console.print(checks)
        if len(rows) > top:
            console.print(
                f"[dim]{len(rows) - top} more; raise --top or use --format json.[/dim]",
                highlight=False,
            )

    if details != "none":
        shown = False
        for res in ordered:
            picked = [f for f in res.findings if fl.severity_at_least(f["severity"], details)]
            if not picked:
                continue
            if not shown:
                console.print()
                console.print(f"[bold]Findings at {details} or worse[/bold]")
                shown = True
            console.print(f"\n[bold]{escape(res.name)}[/bold]")
            for f in picked:
                sev = f["severity"]
                where = f" [dim]{escape(f['file'])}[/dim]" if f["file"] else ""
                console.print(
                    f"  [{_STYLE[sev]}]{sev:<8}[/{_STYLE[sev]}] {escape(f['check'])}{where}\n"
                    f"           {escape(f['message'])}",
                    highlight=False,
                )

    partial = [r for r in results if r.status == "error" or r.exit_code == 3]
    if partial:
        console.print()
        console.print("[bold yellow]Not fully scanned[/bold yellow]")
        reasons: dict[str, list[str]] = {}
        for res in partial:
            for err in res.errors or ["sweep reported missed coverage"]:
                reasons.setdefault(err, []).append(res.name)
        for reason, names in sorted(reasons.items(), key=lambda kv: -len(kv[1])):
            listed = ", ".join(names[:4]) + (
                f" and {len(names) - 4} more" if len(names) > 4 else ""
            )
            console.print(f"  {escape(reason)}\n    [dim]{escape(listed)}[/dim]", highlight=False)

    s = report["summary"]
    found = ", ".join(f"{n} {sev}" for sev, n in s["findings"].items() if n) or "no findings"
    console.print()
    console.print(
        f"[bold]{s['repos']} repositories[/bold]: {s['scanned']} scanned, {s['cached']} from cache, "
        f"{s['errors']} failed, {s['clean']} clean. {found}. {s['seconds']}s.",
        highlight=False,
    )


def fleet(
    targets: list[str] = typer.Argument(
        None, help="Repositories: GitHub URLs, owner/name slugs, or local paths."
    ),
    owner: list[str] = typer.Option(
        None, "--owner", help="Scan every repository of this GitHub user or org (repeatable)."
    ),
    mine: bool = typer.Option(
        False, "--mine", help="Scan every repository of the signed-in GitHub user."
    ),
    root_dir: str = typer.Option(
        None, "--root", help="Scan local git repositories found under this directory."
    ),
    repos_file: str = typer.Option(
        None, "--repos-file", help="File with one repository per line ('-' reads stdin)."
    ),
    only: list[str] = typer.Option(
        None, "--only", help="Sweeps to run (repeatable). Default: the repo-scoped sweeps."
    ),
    spec_file: Path | None = typer.Option(None, "--spec", "-s", help="Spec file."),
    jobs: int = typer.Option(
        0, "--jobs", "-j", help="Repositories scanned at once (default: CPU count, at most 8)."
    ),
    match: list[str] = typer.Option(None, "--match", help="Keep names matching this glob."),
    exclude: list[str] = typer.Option(None, "--exclude", help="Drop names matching this glob."),
    visibility: str = typer.Option(None, "--visibility", help="public or private."),
    pushed_since: str = typer.Option(
        None, "--pushed-since", help="Keep repositories pushed on or after YYYY-MM-DD."
    ),
    include_archived: bool = typer.Option(False, "--include-archived"),
    include_forks: bool = typer.Option(False, "--include-forks"),
    limit: int = typer.Option(
        None, "--limit", min=1, help="Scan at most this many, newest push first."
    ),
    full_history: bool = typer.Option(
        False,
        "--full-history",
        help="Clone full history, so local_history_secrets sees every commit (slower, larger).",
    ),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Ignore and do not write cached results."
    ),
    offline: bool = typer.Option(
        False, "--offline", help="Use cached clones as they are; do not fetch."
    ),
    timeout: int = typer.Option(900, "--timeout", help="Seconds allowed per repository."),
    format: str = typer.Option("text", "--format", "-f", help="text or json."),
    output: str = typer.Option(
        None, "--output", "-o", help="Also write the JSON report or dry-run inventory here."
    ),
    details: str = typer.Option(
        "high",
        "--details",
        help="List individual findings at this severity or worse: "
        "critical, high, medium, low, info, or none.",
    ),
    min_severity: str = typer.Option(
        "low",
        "--min-severity",
        help="Leave repositories and checks with nothing at this severity or worse out of "
        "the tables. Totals always count everything.",
    ),
    top: int = typer.Option(15, "--top", help="Rows in the most-frequent-checks table."),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Exit 2 when a finding is at this severity or worse (or 'never').",
    ),
    full_reports: bool = typer.Option(
        False, "--full-reports", help="Include each sweep's raw report in the JSON."
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="List the repositories and stop."),
) -> None:
    """Sweep many repositories in parallel, with cached clones and results.

    Exit codes: 0 clean, 2 findings at --fail-on or worse, 3 some repository was
    not fully scanned.
    """
    err = Console(stderr=True)
    if format not in ("text", "json"):
        raise typer.BadParameter("expected text or json", param_hint="--format")
    if details != "none" and details not in fl.THRESHOLDS:
        raise typer.BadParameter("expected a severity or none", param_hint="--details")
    if min_severity not in fl.THRESHOLDS:
        raise typer.BadParameter("expected a severity", param_hint="--min-severity")
    if fail_on != "never" and fail_on not in fl.THRESHOLDS:
        raise typer.BadParameter("expected a severity or never", param_hint="--fail-on")
    if visibility and visibility.lower() not in ("public", "private", "internal"):
        raise typer.BadParameter("expected public or private", param_hint="--visibility")
    sweeps = _select_sweeps(only)

    from devguard.spec import resolve_spec_path

    if spec_file is None:
        spec_path = resolve_spec_path()
    else:
        spec_path = spec_file.expanduser()
        if not spec_path.is_file():
            raise typer.BadParameter(f"Expected a spec file at {spec_path}", param_hint="--spec")

    try:
        refs = _collect_refs(targets, owner, mine, root_dir, repos_file, max_depth=3)
    except (ValueError, OSError) as exc:
        err.print(f"[bold red]Error:[/bold red] {escape(str(exc))}", highlight=False)
        raise typer.Exit(code=1) from None
    if not refs and not (dry_run and (mine or owner or root_dir or repos_file)):
        err.print(
            "Nothing to scan. Name repositories, or pass --mine, --owner, --root or --repos-file."
        )
        raise typer.Exit(code=1)
    total = len(refs)
    refs = fl.filter_repos(
        refs,
        include_archived=include_archived,
        include_forks=include_forks,
        visibility=visibility,
        pushed_since=pushed_since,
        match=match,
        exclude=exclude,
        limit=limit,
    )
    if dry_run:
        if format == "json" or output:
            inventory = [
                {
                    "name": ref.name,
                    "path": str(ref.path) if ref.path is not None else None,
                    "visibility": ref.visibility or None,
                    "pushed_at": ref.pushed_at or None,
                }
                for ref in refs
            ]
            _emit_json(inventory, stdout=format == "json", output=output)
        if format == "text":
            for ref in refs:
                sys.stdout.write(
                    f"{ref.name}\t{ref.visibility or '-'}\t{ref.pushed_at[:10] or '-'}\n"
                )
        err.print(f"{len(refs)} of {total} repositories selected.", highlight=False)
        return
    if not refs:
        err.print(f"All {total} repositories were filtered out.", highlight=False)
        raise typer.Exit(code=1)

    workers = jobs if jobs > 0 else min(8, os.cpu_count() or 2)
    workers = min(workers, len(refs))
    started = time.monotonic()
    common = dict(
        sweeps=sweeps,
        spec_path=spec_path if spec_path.is_file() else None,
        jobs=workers,
        use_cache=not no_cache,
        refresh=not offline,
        full_history=full_history,
        timeout=timeout,
    )
    if err.is_terminal:
        with Progress(
            TextColumn("[bold]fleet[/bold]"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("{task.description}"),
            console=err,
            transient=True,
        ) as progress:
            task = progress.add_task(f"{workers} at a time", total=len(refs))

            def tick(res: fl.RepoResult) -> None:
                progress.update(task, advance=1, description=escape(f"{res.name}: {res.status}"))

            results = fl.scan_fleet(refs, on_done=tick, **common)  # type: ignore[arg-type]
    else:
        done = 0

        def log(res: fl.RepoResult) -> None:
            nonlocal done
            done += 1
            sys.stderr.write(f"[{done}/{len(refs)}] {res.name}: {res.status} ({res.seconds}s)\n")

        results = fl.scan_fleet(refs, on_done=log, **common)  # type: ignore[arg-type]

    report = fl.fleet_report(
        results, sweeps=sweeps, seconds=time.monotonic() - started, include_reports=full_reports
    )
    _emit_json(report, stdout=format == "json", output=output)
    if format == "text":
        out = Console()
        if not out.is_terminal:
            # Piped or captured: do not fold the tables to the 80-column default.
            out = Console(width=140)
        _print_text(out, report, results, details, top, min_severity)
        if output:
            err.print(f"JSON report: {output}", highlight=False)

    code = fl.fleet_exit_code(results, fail_on)
    if code == 3 and any(r.counts["unknown"] for r in results) and fail_on != "never":
        err.print("Unrated findings may meet the selected severity threshold.", markup=False)
    if code:
        raise typer.Exit(code=code)


def cache(
    action: str = typer.Argument("info", help="info or clear."),
    results_only: bool = typer.Option(
        False, "--results", help="With clear: drop cached results but keep the clones."
    ),
    as_json: bool = typer.Option(False, "--json", help="With info: print JSON."),
) -> None:
    """Show or clear the clone and result cache used by `fleet` and `sweep --repo URL`."""
    console = Console()
    if action == "info":
        info = fl.cache_info()
        if as_json:
            sys.stdout.write(json.dumps(info, indent=2) + "\n")
            return
        console.print(f"Cache: {info['path']}", highlight=False)
        console.print(
            f"Clones: {info['repos']} ({_human_bytes(info['repo_bytes'])})", highlight=False
        )
        console.print(
            f"Results: {info['results']} ({_human_bytes(info['result_bytes'])})", highlight=False
        )
    elif action == "clear":
        fl.clear_cache(results_only=results_only)
        console.print("Cleared cached results." if results_only else "Cleared the cache.")
    else:
        raise typer.BadParameter("expected info or clear")
