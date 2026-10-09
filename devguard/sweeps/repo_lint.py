"""Repo lint: hygiene checks across a workspace of Rust repos.

Kept separate from the security sweeps: findings are low or info and never
change `devguard sweep`'s exit code. Checks:

- own_crate_pin_drift: a dependency on a crate that lives in the workspace
  whose version requirement excludes the local version
- readme_version_drift: a README `name = "x.y"` line older than Cargo.toml
- cargo_metadata: `documentation` not on docs.rs; missing `rust-version`
- ci_gaps: no workflows, clippy without -D warnings, fuzz targets CI never runs
"""

from __future__ import annotations

import json
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any

from devguard.sweeps._common import iter_git_repos
from devguard.sweeps._common import utc_now as _utc_now

_DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
_SKIP_DIRS = frozenset({"target", "node_modules", ".git", "vendor", "fuzz"})


def _parse_version(text: str) -> tuple[int, int, int] | None:
    m = re.fullmatch(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?", text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))


def requirement_allows(req: str, version: tuple[int, int, int]) -> bool | None:
    """Cargo semantics for bare, ^, ~ and = requirements; None when unsupported."""
    req = req.strip()
    if not req or req == "*" or "," in req or req[0] in "<>":
        return None
    op = ""
    if req[0] in "^~=":
        op, req = req[0], req[1:].strip()
    parts = req.split(".")
    want = _parse_version(req)
    if want is None:
        return None
    if op == "=":
        return version == want
    if version < want:
        return False
    if op == "~":
        # ~1.2.3 and ~1.2 allow 1.2.x; ~1 allows 1.x.
        return version[: min(len(parts), 2)] == want[: min(len(parts), 2)]
    # Caret (also the bare default): the leftmost non-zero component is fixed.
    if want[0] != 0 or len(parts) == 1:
        return version[0] == want[0]
    if want[1] != 0 or len(parts) == 2:
        return version[:2] == want[:2]
    return version == want


def _cargo_manifests(repo: Path) -> list[Path]:
    out: list[Path] = []
    stack = [repo]
    while stack:
        d = stack.pop()
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        for e in entries:
            if (
                e.is_dir()
                and not e.is_symlink()
                and e.name not in _SKIP_DIRS
                and not e.name.startswith(".")
            ):
                if len(e.relative_to(repo).parts) <= 4:
                    stack.append(e)
            elif e.name == "Cargo.toml":
                out.append(e)
    return sorted(out)


def _load(path: Path) -> dict[str, Any] | None:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return None


def _package(data: dict[str, Any], workspace_pkg: dict[str, Any]) -> dict[str, Any] | None:
    pkg = data.get("package")
    if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str):
        return None
    resolved = dict(pkg)
    for key in ("version", "rust-version", "documentation"):
        if isinstance(pkg.get(key), dict) and pkg[key].get("workspace") is True:
            resolved[key] = workspace_pkg.get(key)
    return resolved


def _deps(data: dict[str, Any]) -> list[tuple[str, str]]:
    """(crate name, version requirement) for registry dependencies."""
    out = []
    tables = [data.get(t) for t in _DEP_TABLES]
    for target in (data.get("target") or {}).values():
        if isinstance(target, dict):
            tables += [target.get(t) for t in _DEP_TABLES]
    ws = data.get("workspace")
    if isinstance(ws, dict):
        tables.append(ws.get("dependencies"))
    for table in tables:
        if not isinstance(table, dict):
            continue
        for key, spec in table.items():
            if isinstance(spec, str):
                out.append((key, spec))
            elif (
                isinstance(spec, dict)
                and isinstance(spec.get("version"), str)
                and "path" not in spec
            ):
                out.append((spec.get("package", key), spec["version"]))
    return out


def _released_version(repo: Path, name: str, local: str) -> str | None:
    """The newest released version of a crate: the local version if it is
    tagged, else the newest tag. An untagged repo falls back to the local
    version unless it is a pre-release (`-dev`), which says it is unreleased.
    """
    res = subprocess.run(
        ["git", "-C", str(repo), "tag", "--list"], capture_output=True, text=True, timeout=30
    )
    tag_re = re.compile(rf"^(?:{re.escape(name)}-)?v?(\d+\.\d+\.\d+)$")
    tagged = sorted(
        (
            v
            for t in res.stdout.split()
            if (m := tag_re.match(t)) and (v := _parse_version(m.group(1)))
        ),
        reverse=True,
    )
    lv = _parse_version(local)
    if lv and lv in tagged:
        return local
    if tagged:
        return ".".join(map(str, tagged[0]))
    return None if "-" in local else local


def _finding(repo: Path, check: str, severity: str, message: str, file: str) -> dict[str, Any]:
    return {
        "repo_path": str(repo),
        "check": check,
        "severity": severity,
        "message": message,
        "file": file,
    }


def lint_repos(
    *,
    dev_root: Path,
    max_depth: int,
    exclude_repo_globs: list[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    repos = sorted(iter_git_repos(dev_root, max_depth=max_depth, exclude_globs=exclude_repo_globs))
    manifests: dict[Path, list[tuple[Path, dict[str, Any], dict[str, Any] | None]]] = {}
    local_versions: dict[str, tuple[str, str]] = {}  # crate -> (version, repo name)
    for repo in repos:
        entries = []
        loaded = [(m, _load(m)) for m in _cargo_manifests(repo)]
        ws_pkg: dict[str, Any] = {}
        for _, data in loaded:
            ws = (data or {}).get("workspace")
            if isinstance(ws, dict) and isinstance(ws.get("package"), dict):
                ws_pkg = ws["package"]
        for m, data in loaded:
            if data is None:
                errors.append(f"{m}: unparseable Cargo.toml")
                continue
            pkg = _package(data, ws_pkg)
            entries.append((m, data, pkg))
            if pkg and isinstance(pkg.get("version"), str) and pkg.get("publish") is not False:
                released = _released_version(repo, pkg["name"], pkg["version"])
                if released:
                    local_versions.setdefault(pkg["name"], (released, repo.name))
        manifests[repo] = entries

    findings: list[dict[str, Any]] = []
    for repo, entries in manifests.items():
        own = {pkg["name"] for _, _, pkg in entries if pkg}
        for m, data, pkg in entries:
            rel = str(m.relative_to(repo))
            for name, req in _deps(data):
                if name in own or name not in local_versions:
                    continue
                local, where = local_versions[name]
                lv = _parse_version(local)
                if lv and requirement_allows(req, lv) is False:
                    findings.append(
                        _finding(
                            repo,
                            "own_crate_pin_drift",
                            "low",
                            f'{name} = "{req}" excludes the released {name} {local} ({where})',
                            rel,
                        )
                    )
            if not pkg or pkg.get("publish") is False:
                continue
            doc = pkg.get("documentation")
            if isinstance(doc, str) and doc and "docs.rs" not in doc:
                findings.append(
                    _finding(
                        repo,
                        "cargo_metadata",
                        "low",
                        f"{pkg['name']}: documentation points to {doc}, not docs.rs",
                        rel,
                    )
                )
            if not pkg.get("rust-version"):
                findings.append(
                    _finding(
                        repo,
                        "cargo_metadata",
                        "info",
                        f"{pkg['name']}: no rust-version (MSRV) declared",
                        rel,
                    )
                )
            version = pkg.get("version")
            # Honor `readme = "../../README.md"` in workspace member crates.
            readme_key = pkg.get("readme")
            readme = (
                (m.parent / readme_key) if isinstance(readme_key, str) else m.parent / "README.md"
            )
            readme = readme.resolve()
            in_repo = readme.is_relative_to(repo.resolve())
            # A -dev version is unreleased; a README pinning the last release is right.
            if isinstance(version, str) and "-" not in version and in_repo and readme.is_file():
                lv = _parse_version(version)
                text = readme.read_text(encoding="utf-8", errors="replace")
                for rm in re.finditer(rf'^\s*{re.escape(pkg["name"])}\s*=\s*"([^"]+)"', text, re.M):
                    if lv and requirement_allows(rm.group(1), lv) is False:
                        findings.append(
                            _finding(
                                repo,
                                "readme_version_drift",
                                "low",
                                f'README says {pkg["name"]} = "{rm.group(1)}" but Cargo.toml is {version}',
                                str(readme.relative_to(repo.resolve())),
                            )
                        )
                        break
        if entries:
            findings.extend(_ci_gaps(repo))

    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {"dev_root": str(dev_root), "max_depth": max_depth, "repos_scanned": len(repos)},
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "by_check": {
                c: sum(1 for f in findings if f["check"] == c)
                for c in sorted({f["check"] for f in findings})
            },
        },
        "errors": errors,
    }
    return report, errors


def _ci_gaps(repo: Path) -> list[dict[str, Any]]:
    wf_dir = repo / ".github" / "workflows"
    workflows = sorted(wf_dir.glob("*.y*ml")) if wf_dir.is_dir() else []
    if not workflows:
        return [
            _finding(
                repo, "ci_gaps", "low", "Rust repo with no GitHub workflows", ".github/workflows/"
            )
        ]
    text = "\n".join(w.read_text(encoding="utf-8", errors="replace") for w in workflows)
    out = []
    if "clippy" in text and not re.search(r"-D\s*warnings|-Dwarnings", text):
        out.append(
            _finding(
                repo,
                "ci_gaps",
                "low",
                "clippy runs without -D warnings, so lints never fail CI",
                ".github/workflows/",
            )
        )
    if (repo / "fuzz").is_dir() and not re.search(r"cargo\s+(?:\+\S+\s+)?fuzz\s+run", text):
        out.append(
            _finding(
                repo, "ci_gaps", "low", "fuzz/ exists but no workflow runs cargo fuzz", "fuzz/"
            )
        )
    return out


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
