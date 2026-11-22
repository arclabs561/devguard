"""Optional local import-graph evidence for fleet findings."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


def _relative(location: str, root: Path) -> str | None:
    path = Path(location)
    if path.is_absolute():
        try:
            path = path.relative_to(root)
        except ValueError:
            return None
    return path.as_posix() if ".." not in path.parts else None


def _reports(exe: str, root: Path, cwd: str, args: list[str], deadline: float) -> list[dict]:
    # The Go resolver may call go list. Keep graph inspection offline.
    env = {**os.environ, "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local"}
    run = subprocess.run(
        [exe, "files", str(root), "--include-tests", "--store", "false", "--format", "json", *args],
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=max(0.01, deadline - time.monotonic()),
        check=False,
    )
    if run.returncode:
        raise ValueError(f"pkgrank exited {run.returncode}")
    # 0.5.1 prints the affected paths in a second JSON document. Later versions
    # include them in the files document. Accept only these two contracts.
    data = run.stdout.strip()
    first, end = json.JSONDecoder().raw_decode(data)
    reports = [first]
    if rest := data[end:].strip():
        reports.append(json.loads(rest))
    if not all(isinstance(obj, dict) for obj in reports):
        raise ValueError("unexpected pkgrank report")
    if (
        first.get("schema_version") != 1
        or first.get("ok") is not True
        or first.get("command") != "files"
    ):
        raise ValueError("unsupported pkgrank files report")
    return reports


def rank_findings(root: Path, findings: list[dict[str, Any]], timeout: int) -> dict[str, Any]:
    """Attach the highest-reach matching file to each finding. Never change its severity."""
    locations = [
        {
            rel
            for item in [f.get("file"), *f.get("files", [])]
            if isinstance(item, str) and item
            if (rel := _relative(item, root)) is not None
        }
        for f in findings
    ]
    if not any(locations):
        return {"status": "no_locations", "matched_findings": 0}
    exe = shutil.which("pkgrank")
    if not exe:
        return {"status": "unavailable", "reason": "pkgrank was not found on PATH"}
    deadline = time.monotonic() + timeout
    try:
        with tempfile.TemporaryDirectory(prefix="devguard-pkgrank-") as cwd:
            (graph,) = _reports(
                str(Path(exe).resolve()), root, cwd, ["--top", "2147483647"], deadline
            )
            rows = graph["rows"]
            if not isinstance(rows, list) or graph.get("rows_total") != len(rows):
                raise ValueError("incomplete pkgrank file list")
            index = {}
            for row in rows:
                if (
                    not isinstance(row, dict)
                    or not isinstance(row.get("file"), str)
                    or Path(row["file"]).is_absolute()
                    or ".." in Path(row["file"]).parts
                    or not isinstance(row.get("role"), str)
                ):
                    raise ValueError("invalid pkgrank file row")
                if (
                    type(row.get("dependents")) is not int
                    or row["dependents"] < 0
                    or row["file"] in index
                ):
                    raise ValueError("invalid pkgrank dependent count or duplicate file")
                index[row["file"]] = row

            # Git can list tracked files already removed from a dirty checkout.
            # Their old nodes can also affect the reach reported for surviving files.
            missing = sorted(file for file in index if not (root / file).is_file())
            if missing:
                return {
                    "status": "unavailable",
                    "reason": "pkgrank listed files missing from the checkout",
                    "missing_files": missing,
                }
            nested = graph.get("unscanned_projects", [])
            if not isinstance(nested, list) or any(
                not isinstance(project, dict)
                or not isinstance(project.get("ecosystem"), str)
                or not isinstance(project.get("manifest"), str)
                or not project["manifest"]
                or Path(project["manifest"]).is_absolute()
                or ".." in Path(project["manifest"]).parts
                for project in nested
            ):
                raise ValueError("invalid unscanned project list")
            seeds: set[str] = set()
            unmatched: set[str] = set()
            matched = 0
            for finding, paths in zip(findings, locations, strict=True):
                files = set()
                for path in paths:
                    # Prefer an exact filename, including a literal colon, over a line suffix.
                    file = path if path in index else re.sub(r":\d+(?::\d+)?$", "", path)
                    if file in index:
                        files.add(file)
                    else:
                        unmatched.add(file)
                if files:
                    matched += 1
                    seeds.update(files)
                    best = min(files, key=lambda f: (-index[f]["dependents"], f))
                    finding["pkgrank"] = {
                        "file": best,
                        "dependents": index[best]["dependents"],
                        "matched_files": sorted(files),
                    }
            context: dict[str, Any] = {
                "status": "ranked",
                "matched_findings": matched,
                "files_in_graph": len(rows),
                "ecosystem": graph.get("ecosystem"),
            }
            if nested:
                context["status"] = "partial"
                context["unscanned_projects"] = nested
            if not rows:
                context["status"] = "empty"
            if unmatched:
                context["unmatched_files"] = sorted(unmatched)
            if not seeds:
                context["tests_unavailable"] = "no finding paths matched the file graph"
                return context
            if not any(index[f]["dependents"] for f in seeds):
                # No imports lead back to these files. A flagged test itself still
                # needs to run, even on pkgrank releases that omit an empty traversal.
                context["candidate_tests"] = sorted(f for f in seeds if index[f]["role"] == "test")
                return context
            # Exact graph members only. pkgrank also supports fuzzy input for interactive use.
            arg = ",".join(sorted(seeds))
            if any("," in f for f in seeds) or len(os.fsencode(arg)) > 24000:
                context["tests_unavailable"] = (
                    "selection exceeds the portable --affected argument format"
                )
                return context
            try:
                reports = _reports(
                    str(Path(exe).resolve()), root, cwd, ["--top", "0", "--affected", arg], deadline
                )
                impact = reports[-1]
                affected = impact["affected"]
                if (
                    not isinstance(affected, list)
                    or not all(isinstance(f, str) and f in index for f in affected)
                    or impact.get("affected_count") != len(affected)
                    or impact.get("changed") != sorted(seeds)
                ):
                    raise ValueError("invalid pkgrank affected-file report")
                selected = sorted(f for f in seeds.union(affected) if index[f]["role"] == "test")
                missing = [f for f in selected if not (root / f).is_file()]
                if missing:
                    context["tests_unavailable"] = "test files disappeared during selection"
                    context["missing_files"] = missing
                else:
                    context["candidate_tests"] = selected
            except (ValueError, KeyError, OSError, subprocess.TimeoutExpired):
                context["tests_unavailable"] = "pkgrank could not resolve affected test files"
            return context
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as exc:
        reason = (
            "pkgrank timed out"
            if isinstance(exc, subprocess.TimeoutExpired)
            else "pkgrank could not provide a complete file graph"
        )
        return {"status": "unavailable", "reason": reason}
