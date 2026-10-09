"""Repo hygiene sweep: detect structural problems across local git repos.

Checks each repo for scattered doc dirs, committed generated data, hardcoded
absolute paths in shell scripts, stale .gitkeep files, tracked editor/cache
directories, internal documents in public repos, stale rename references,
and declaration-only [workspace.dependencies] entries.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import dotenv_values

from devguard.sweeps._common import default_dev_root as _default_dev_root
from devguard.sweeps._common import iter_git_repos
from devguard.sweeps._common import utc_now as _utc_now

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class HygieneFinding:
    repo_path: str
    check: str
    severity: str  # "low" or "medium"
    message: str
    files: list[str] = field(default_factory=list)


@dataclass
class RepoHygieneResult:
    repo_path: str
    is_public: bool
    findings: list[HygieneFinding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_likely_public(repo: Path) -> bool:
    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"):
        if (repo / name).exists():
            return True
    return False


def _git_ls_files(repo: Path) -> list[str]:
    """Return all tracked file paths (relative) for a repo."""
    proc = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
    )
    if proc.returncode != 0:
        return []
    out = proc.stdout.decode("utf-8", errors="replace")
    return [p for p in out.split("\0") if p]


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _check_scattered_docs(repo: Path) -> HygieneFinding | None:
    """A: Both doc/ and docs/ exist at repo root."""
    has_doc = (repo / "doc").is_dir()
    has_docs = (repo / "docs").is_dir()
    if has_doc and has_docs:
        return HygieneFinding(
            repo_path=str(repo),
            check="scattered_docs",
            severity="low",
            message="Both doc/ and docs/ exist at repo root -- consolidate into one.",
            files=["doc/", "docs/"],
        )
    return None


# Glob patterns for generated data that shouldn't normally be committed.
_GENERATED_DATA_GLOBS: list[str] = [
    "data/**/*.json",
    "data/**/*.jsonl",
    "data/**/*.csv",
    "data/**/*.bin",
    "data/**/*.hdf5",
    "results/**/*.json",
    "output/**/*.json",
    ".hypothesis/constants/*",
]

# Directories that signal data/ is intentional (contains project manifests).
_DATA_INTENTIONAL_MARKERS: tuple[str, ...] = ("Cargo.toml", "package.json", "pyproject.toml")


def _data_dir_is_intentional(repo: Path) -> bool:
    data = repo / "data"
    if not data.is_dir():
        return False
    for marker in _DATA_INTENTIONAL_MARKERS:
        if (data / marker).exists():
            return True
    return False


def _check_committed_generated_data(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """B: Tracked files matching generated-data patterns."""
    if _data_dir_is_intentional(repo):
        # data/ is a source tree; only check non-data patterns
        active_globs = [g for g in _GENERATED_DATA_GLOBS if not g.startswith("data/")]
    else:
        active_globs = _GENERATED_DATA_GLOBS

    matched: list[str] = []
    for rel in tracked:
        for g in active_globs:
            if fnmatch.fnmatch(rel, g):
                matched.append(rel)
                break

    if not matched:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="committed_generated_data",
        severity="medium",
        message=f"{len(matched)} tracked file(s) look like generated/data artifacts.",
        files=matched[:20],
    )


# A home directory with a real-looking user name: /Users/<name>/, /home/<name>/
# or C:\Users\<name>\. Generic names used by CI and docs are allowed.
_HARDCODED_PATH_RE = re.compile(
    r"(?:/Users/|/home/|[A-Za-z]:\\\\?Users\\\\?)([A-Za-z0-9._-]+)[/\\]"
)
_GENERIC_HOME_NAMES = frozenset(
    {
        "runner",
        "user",
        "username",
        "example",
        "you",
        "me",
        "name",
        "someone",
        "shared",
        "ubuntu",
        "admin",
        "root",
        "vscode",
        "node",
        "app",
        "dev",
        "jovyan",
        "circleci",
    }
)
_TEXT_SCAN_MAX_BYTES = 1024 * 1024
_TEXT_SKIP_GLOBS = ("*.lock", "*.min.*", "*.svg", "*.map", "*search-index*.js", "package-lock.json")


def _tracked_text(repo: Path, rel: str) -> str | None:
    """Text of a tracked regular file, or None for links, binaries and big files."""
    if any(fnmatch.fnmatch(Path(rel).name, g) for g in _TEXT_SKIP_GLOBS):
        return None
    path = repo / rel
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _TEXT_SCAN_MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def _check_hardcoded_paths(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """C: Tracked text files containing a personal home-directory path."""
    hits: list[str] = []
    for rel in tracked:
        text = _tracked_text(repo, rel)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if any(
                m.group(1).lower() not in _GENERIC_HOME_NAMES
                for m in _HARDCODED_PATH_RE.finditer(line)
            ):
                hits.append(f"{rel}:{lineno}")
                break  # one location per file keeps the report readable
        if len(hits) >= 20:
            break

    if not hits:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="hardcoded_absolute_paths",
        severity="medium",
        message=(
            f"Personal home-directory path in {len(hits)} tracked file(s) -- it leaks a "
            "user name and breaks on other machines."
        ),
        files=hits,
    )


_SECRET_LIKE_NAME_RE = re.compile(
    r"^(?:\.env(?:\.(?!example|sample|template|dist)[\w.-]+)?|.*\.(?:pem|key|p12|pfx)|id_[rd]sa|"
    r"id_ed25519|credentials(?:\.json)?|\.netrc|\.npmrc|\.pypirc)$",
    re.IGNORECASE,
)


def _check_tracked_ignored(repo: Path) -> HygieneFinding | None:
    """I: Tracked files that the repo's own ignore rules say should not be tracked."""
    proc = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z", "--cached", "--ignored", "--exclude-standard"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
    )
    if proc.returncode != 0:
        return None
    files = [p for p in proc.stdout.decode("utf-8", errors="replace").split("\0") if p]
    if not files:
        return None
    secret_like = [f for f in files if _SECRET_LIKE_NAME_RE.match(Path(f).name)]
    return HygieneFinding(
        repo_path=str(repo),
        check="tracked_but_ignored",
        severity="medium" if secret_like else "low",
        message=(
            f"{len(files)} tracked file(s) match the repo's ignore rules"
            + (f", {len(secret_like)} with secret-like names" if secret_like else "")
            + " -- untrack them (git rm --cached) or narrow the rule."
        ),
        files=(secret_like + [f for f in files if f not in secret_like])[:20],
    )


_HISTORY_BLOB_LIMIT = 5 * 1024 * 1024
# Build output and caches that should never have been committed at all.
_ARTIFACT_PATH_RE = re.compile(
    r"(?:^|/)(?:target|node_modules|__pycache__|\.fastembed_cache|\.venv)/"
    r"|\.(?:rlib|rmeta|so|dylib|o|a|pyc|onnx)$|(?:^|/)\.DS_Store$"
)


def _check_history_bloat(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """K: Large blobs or build artifacts anywhere in history, not just the tree.

    Every clone downloads them; deleting the file from HEAD does not help.
    """
    revs = subprocess.run(
        ["git", "-C", str(repo), "rev-list", "--objects", "--all"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=120,
    )
    if revs.returncode != 0 or not revs.stdout:
        return None
    sizes = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "cat-file",
            "--batch-check=%(objecttype) %(objectsize) %(rest)",
        ],
        input=revs.stdout,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=120,
    )
    if sizes.returncode != 0:
        return None
    in_head = set(tracked)
    big: dict[str, int] = {}
    artifacts: set[str] = set()
    for line in sizes.stdout.decode("utf-8", errors="replace").splitlines():
        kind, _, rest = line.partition(" ")
        if kind != "blob":
            continue
        size_s, _, path = rest.partition(" ")
        if not path:
            continue
        size = int(size_s)
        if size > _HISTORY_BLOB_LIMIT:
            big[path] = max(size, big.get(path, 0))
        if _ARTIFACT_PATH_RE.search(path) and path not in in_head:
            artifacts.add(path)
    if not big and not artifacts:
        return None
    total_mb = sum(big.values()) / (1024 * 1024)
    files = [
        f"{p} ({s / (1024 * 1024):.1f} MiB{'' if p in in_head else ', history only'})"
        for p, s in sorted(big.items(), key=lambda kv: -kv[1])
    ]
    files += sorted(artifacts)
    parts = []
    if big:
        parts.append(f"{len(big)} blob(s) over 5 MiB ({total_mb:.0f} MiB)")
    if artifacts:
        parts.append(f"{len(artifacts)} build artifact path(s) no longer in HEAD")
    return HygieneFinding(
        repo_path=str(repo),
        check="history_bloat",
        severity="medium" if total_mb > 50 else "low",
        message=(
            f"History holds {' and '.join(parts)}; every clone downloads them. "
            "Removing them needs a history rewrite (git filter-repo)."
        ),
        files=files[:20],
    )


def _check_local_path_deps(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """J: Dependencies on paths outside the repo, which break clones and publishes."""
    repo_real = repo.resolve()

    def outside(base: Path, target: str) -> bool:
        try:
            (base / target).resolve().relative_to(repo_real)
        except ValueError:
            return True
        return False

    hits: list[str] = []
    for rel in tracked:
        name = Path(rel).name
        base = (repo / rel).parent
        if name == "package.json":
            try:
                data = json.loads((repo / rel).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for table in (
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ):
                deps = data.get(table) if isinstance(data, dict) else None
                for dep, spec in (deps or {}).items():
                    if isinstance(spec, str) and spec.startswith(("file:", "link:")):
                        target = spec.split(":", 1)[1]
                        if outside(base, target):
                            hits.append(f"{rel}: {dep} -> {spec}")
        elif name == "Cargo.toml":
            data = _parse_toml(repo / rel)
            if data is None:
                continue
            for target in _path_deps(data):
                if outside(base, target):
                    hits.append(f"{rel}: path = {target}")
        elif name == "pyproject.toml":
            data = _parse_toml(repo / rel)
            sources = ((data or {}).get("tool", {}).get("uv", {}) or {}).get("sources", {})
            for dep, src in (sources or {}).items():
                if isinstance(src, dict) and isinstance(src.get("path"), str):
                    if outside(base, src["path"]):
                        hits.append(f"{rel}: {dep} -> {src['path']}")
    if not hits:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="local_path_dependency",
        severity="medium",
        message=(
            f"{len(hits)} dependency(ies) point outside the repo -- a fresh clone or a "
            "published package cannot resolve them."
        ),
        files=hits[:20],
    )


def _check_stale_gitkeep(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """D: .gitkeep file in a directory that also has other tracked files."""
    # Build a map from directory -> tracked file count (excluding .gitkeep itself)
    dir_other: dict[str, int] = {}
    gitkeep_dirs: list[str] = []

    for rel in tracked:
        p = Path(rel)
        parent = str(p.parent)
        if p.name == ".gitkeep":
            gitkeep_dirs.append(parent)
        else:
            dir_other[parent] = dir_other.get(parent, 0) + 1

    stale: list[str] = []
    for d in gitkeep_dirs:
        if dir_other.get(d, 0) > 0:
            stale.append(f"{d}/.gitkeep")

    if not stale:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="stale_gitkeep",
        severity="low",
        message=f"{len(stale)} .gitkeep file(s) in directories that have other tracked files.",
        files=stale,
    )


_TRACKED_EDITOR_DIRS: tuple[str, ...] = (
    ".vscode/",
    ".idea/",
    ".ruff_cache/",
    ".hypothesis/",
)


def _check_tracked_editor_dirs(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """E: Editor/cache directories tracked in git."""
    found: set[str] = set()
    for rel in tracked:
        for prefix in _TRACKED_EDITOR_DIRS:
            if rel.startswith(prefix) or ("/" + prefix) in rel:
                found.add(prefix.rstrip("/"))
                break

    if not found:
        return None
    dirs = sorted(found)
    return HygieneFinding(
        repo_path=str(repo),
        check="tracked_editor_dirs",
        severity="low",
        message=f"Editor/cache directory tracked in git: {', '.join(dirs)}.",
        files=[d + "/" for d in dirs],
    )


_INTERNAL_DOC_PATTERNS: list[str] = [
    "*AUDIT*.md",
    "*_REVIEW*.md",
    ".claude/*session*.json",
    ".trainctl/*session*.json",
]


def _check_internal_docs_in_public(
    repo: Path, tracked: list[str], is_public: bool
) -> HygieneFinding | None:
    """F: Internal documents committed in a public repo."""
    if not is_public:
        return None

    matched: list[str] = []
    for rel in tracked:
        for pat in _INTERNAL_DOC_PATTERNS:
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(Path(rel).name, pat):
                matched.append(rel)
                break

    if not matched:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="internal_docs_in_public_repo",
        severity="low",
        message=f"{len(matched)} internal document(s) committed in a public repo.",
        files=matched,
    )


_TEXT_POLICY_BINARY_SUFFIXES: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bin",
        ".wasm",
        ".so",
        ".dylib",
        ".pdf",
        ".zip",
        ".gz",
    }
)


def _split_env_patterns(value: str) -> list[str]:
    """Split newline/comma-separated regex policy values."""
    return [item.strip() for item in re.split(r"[\n,]+", value) if item.strip()]


def _environment_with_dotenv() -> dict[str, str]:
    dotenv_env: dict[str, str] = {}
    for path in (Path("../.env"), Path(".env")):
        if not path.exists():
            continue
        for key, value in dotenv_values(path).items():
            if value is not None:
                dotenv_env[key] = value
    return {**dotenv_env, **os.environ}


def _configured_public_text_patterns(
    patterns: list[str] | None,
    patterns_env: str | None,
) -> tuple[list[re.Pattern[str]], list[str]]:
    """Compile public text policy regexes without exposing their source values."""
    raw_patterns = [p for p in (patterns or []) if isinstance(p, str) and p.strip()]
    if patterns_env:
        raw_patterns.extend(_split_env_patterns(_environment_with_dotenv().get(patterns_env, "")))

    compiled: list[re.Pattern[str]] = []
    errors: list[str] = []
    for idx, pattern in enumerate(raw_patterns, 1):
        try:
            compiled.append(re.compile(pattern))
        except re.error as exc:
            errors.append(f"public_text_patterns[{idx}] failed to compile: {exc}")
    return compiled, errors


def _text_policy_file_selected(rel: str, file_globs: list[str]) -> bool:
    if not file_globs:
        return True
    return any(
        fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(Path(rel).name, glob) for glob in file_globs
    )


def _check_public_text_patterns(
    repo: Path,
    tracked: list[str],
    is_public: bool,
    patterns: list[re.Pattern[str]],
    file_globs: list[str],
) -> HygieneFinding | None:
    """Flag configured private/workspace terms in tracked public-repo text."""
    if not is_public or not patterns:
        return None

    hits: list[str] = []
    total = 0
    for rel in tracked:
        if not _text_policy_file_selected(rel, file_globs):
            continue
        path = repo / rel
        if not path.is_file() or path.suffix.lower() in _TEXT_POLICY_BINARY_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if any(pattern.search(line) for pattern in patterns):
                total += 1
                hits.append(f"{rel}:{lineno}")
                if len(hits) >= 20:
                    break
        if len(hits) >= 20:
            break

    if not hits:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="public_text_policy",
        severity="medium",
        message=f"{total} tracked public text location(s) matched the configured leak policy.",
        files=hits,
    )


def _check_stale_rename_refs(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """G: Cargo.toml name differs from directory name; old name still appears as env var prefix."""
    cargo = repo / "Cargo.toml"
    if not cargo.is_file():
        return None

    dir_name = repo.name

    try:
        cargo_text = cargo.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None

    # Extract package name from [package] name = "..."
    name_match = re.search(r'^\s*name\s*=\s*"([^"]+)"', cargo_text, re.MULTILINE)
    if not name_match:
        return None
    crate_name = name_match.group(1)

    # Only flag when crate name and directory name differ
    # (normalize hyphens to underscores for comparison)
    crate_norm = crate_name.replace("-", "_")
    dir_norm = dir_name.replace("-", "_")
    if crate_norm == dir_norm:
        return None

    # The old name candidate is the directory name (the one that changed)
    old_prefix = dir_norm.upper()
    pattern = re.compile(r"\b" + re.escape(old_prefix) + r"_\w+")

    hits: list[str] = []
    count = 0
    for rel in tracked:
        path = repo / rel
        if not path.is_file():
            continue
        # Only scan text-like files; skip binaries by extension
        suffix = path.suffix.lower()
        if suffix in (".png", ".jpg", ".jpeg", ".gif", ".bin", ".wasm", ".so", ".dylib"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        matches = pattern.findall(text)
        if matches:
            count += len(matches)
            hits.append(f"{rel} ({len(matches)} ref(s))")

    # Heuristic threshold: only flag if more than 3 references remain
    if count <= 3:
        return None

    return HygieneFinding(
        repo_path=str(repo),
        check="stale_rename_refs",
        severity="medium",
        message=(
            f"Cargo.toml name={crate_name!r} differs from dir={dir_name!r}; "
            f"{count} reference(s) to old env var prefix {old_prefix!r} remain."
        ),
        files=hits[:10],
    )


_CARGO_DEP_TABLES: tuple[str, ...] = ("dependencies", "dev-dependencies", "build-dependencies")

# Directory names skipped when walking a repo for Cargo.toml manifests.
_MANIFEST_WALK_JUNK: frozenset[str] = frozenset(
    {"target", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}
)


def _find_cargo_manifests(repo: Path, max_depth: int = 6) -> list[str]:
    """Find Cargo.toml files under *repo* (relative paths), skipping junk dirs.

    Walks the filesystem rather than `git ls-files` so that untracked member
    manifests still count as consumers (cargo reads the filesystem, not git).
    """
    found: list[str] = []
    stack: list[tuple[Path, int]] = [(repo, 0)]
    while stack:
        cur, depth = stack.pop()
        manifest = cur / "Cargo.toml"
        if manifest.is_file():
            found.append(str(manifest.relative_to(repo)))
        if depth >= max_depth:
            continue
        try:
            for child in cur.iterdir():
                if not child.is_dir():
                    continue
                name = child.name
                if name in _MANIFEST_WALK_JUNK or name.startswith("."):
                    continue
                stack.append((child, depth + 1))
        except Exception:
            continue
    return sorted(found)


def _parse_toml(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except Exception:
        return None


def _dep_tables(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """All dependency tables of one manifest, including [target.*] variants."""
    tables: list[dict[str, Any]] = []
    for tbl in _CARGO_DEP_TABLES:
        val = manifest.get(tbl)
        if isinstance(val, dict):
            tables.append(val)
    target = manifest.get("target")
    if isinstance(target, dict):
        for cfg in target.values():
            if not isinstance(cfg, dict):
                continue
            for tbl in _CARGO_DEP_TABLES:
                val = cfg.get(tbl)
                if isinstance(val, dict):
                    tables.append(val)
    return tables


def _workspace_dep_consumers(manifest: dict[str, Any]) -> set[str]:
    """Keys a single manifest consumes with `workspace = true`.

    Covers [dependencies]/[dev-dependencies]/[build-dependencies] plus the
    [target.*.dependencies] variants. Both `key = { workspace = true, ... }`
    and dotted `key.workspace = true` parse to the same dict shape. The key
    is what matters: `foo = { workspace = true }` consumes the workspace
    entry `foo` even when that entry renames via `package = "bar"`.
    """
    consumed: set[str] = set()
    for table in _dep_tables(manifest):
        for key, val in table.items():
            if isinstance(val, dict) and val.get("workspace") is True:
                consumed.add(key)
    return consumed


def _path_deps(manifest: dict[str, Any]) -> list[str]:
    """Relative `path = "..."` dependency targets of one manifest."""
    out: list[str] = []
    for table in _dep_tables(manifest):
        for val in table.values():
            if isinstance(val, dict) and isinstance(val.get("path"), str):
                out.append(val["path"])
    return out


def _resolve_member_manifests(
    ws_dir: Path, root_data: dict[str, Any]
) -> tuple[list[dict[str, Any]], bool]:
    """Resolve a workspace's member manifests per cargo semantics.

    Members = root package (if any) + glob-expanded `workspace.members` +
    transitive in-tree path dependencies of members, minus `workspace.exclude`.
    Returns (parsed member manifests, all_parsed); all_parsed is False when
    any member manifest failed to parse.
    """
    ws_dir = ws_dir.resolve()
    workspace = root_data.get("workspace")
    workspace = workspace if isinstance(workspace, dict) else {}

    raw_exclude = workspace.get("exclude")
    exclude = (
        [e for e in raw_exclude if isinstance(e, str)] if isinstance(raw_exclude, list) else []
    )

    def _is_excluded(d: Path) -> bool:
        try:
            rel = d.relative_to(ws_dir)
        except ValueError:
            return True  # outside the workspace dir -> never a member
        return any(fnmatch.fnmatch(str(rel), pat) for pat in exclude)

    pending: list[Path] = []
    if isinstance(root_data.get("package"), dict):
        pending.append(ws_dir)
    raw_members = workspace.get("members")
    if isinstance(raw_members, list):
        for pat in raw_members:
            if not isinstance(pat, str):
                continue
            for hit in sorted(ws_dir.glob(pat)):
                if (hit / "Cargo.toml").is_file():
                    pending.append(hit)

    seen: set[Path] = set()
    parsed: list[dict[str, Any]] = []
    all_parsed = True
    while pending:
        d = pending.pop().resolve()
        if d in seen or _is_excluded(d):
            continue
        seen.add(d)
        data = _parse_toml(d / "Cargo.toml") if d != ws_dir else root_data
        if data is None:
            all_parsed = False
            continue
        parsed.append(data)
        # Path dependencies of members are automatically members themselves.
        for dep_path in _path_deps(data):
            cand = d / dep_path
            if (cand / "Cargo.toml").is_file():
                pending.append(cand)
    return parsed, all_parsed


def _check_unused_workspace_deps(repo: Path) -> HygieneFinding | None:
    """H: [workspace.dependencies] keys that no workspace member consumes.

    Declaration-only keys read as real dependency edges to TOML-level
    scanners (devpulse local_dependents, pkgrank) and cause phantom bump
    commits. Consumers are the actual cargo member set (root package,
    `members` globs, transitive in-tree path deps, minus `exclude`),
    including the root manifest's own dep tables for single-crate
    workspaces. A workspace with any unparseable member manifest is
    skipped -- non-consumption can't be proven.
    """
    manifests = _find_cargo_manifests(repo)
    if not manifests:
        return None

    dead: list[str] = []
    for rel in manifests:
        data = _parse_toml(repo / rel)
        if data is None:
            continue
        workspace = data.get("workspace")
        if not isinstance(workspace, dict):
            continue
        ws_deps = workspace.get("dependencies")
        if not isinstance(ws_deps, dict) or not ws_deps:
            continue
        members, all_parsed = _resolve_member_manifests((repo / rel).parent, data)
        if not all_parsed:
            continue
        consumed: set[str] = set()
        for member in members:
            consumed |= _workspace_dep_consumers(member)
        dead.extend(f"{rel}: {key}" for key in sorted(set(ws_deps) - consumed))

    if not dead:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="unused_workspace_deps",
        severity="low",
        message=(
            f"{len(dead)} [workspace.dependencies] key(s) with no `workspace = true` "
            "consumer -- delete the entry, or consume it via "
            "`<key> = { workspace = true }` in a member manifest."
        ),
        files=dead[:20],
    )


# ---------------------------------------------------------------------------
# Main sweep function
# ---------------------------------------------------------------------------


def sweep_repo_hygiene(
    *,
    dev_root: Path | None = None,
    max_depth: int = 2,
    exclude_repo_globs: list[str] | None = None,
    public_text_patterns: list[str] | None = None,
    public_text_patterns_env: str | None = None,
    public_text_file_globs: list[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Check repos for structural hygiene problems and return a report."""
    errors: list[str] = []
    root = dev_root if dev_root is not None else _default_dev_root()
    text_patterns, pattern_errors = _configured_public_text_patterns(
        public_text_patterns,
        public_text_patterns_env,
    )
    errors.extend(pattern_errors)
    text_file_globs = [
        g for g in (public_text_file_globs or []) if isinstance(g, str) and g.strip()
    ]

    repos = sorted(iter_git_repos(root, max_depth=max_depth))
    globs = [g for g in (exclude_repo_globs or []) if isinstance(g, str) and g.strip()]
    if globs:
        repos = [r for r in repos if not any(fnmatch.fnmatch(str(r), g) for g in globs)]

    results: list[RepoHygieneResult] = []
    total_findings = 0

    for repo in repos:
        try:
            is_public = _is_likely_public(repo)
            tracked = _git_ls_files(repo)
        except Exception as exc:
            errors.append(f"failed to read {repo}: {exc}")
            continue

        result = RepoHygieneResult(repo_path=str(repo), is_public=is_public)

        for check_fn in (
            lambda r: _check_scattered_docs(r),
            lambda r: _check_committed_generated_data(r, tracked),
            lambda r: _check_hardcoded_paths(r, tracked),
            lambda r: _check_stale_gitkeep(r, tracked),
            lambda r: _check_tracked_editor_dirs(r, tracked),
            lambda r: _check_internal_docs_in_public(r, tracked, is_public),
            lambda r: _check_public_text_patterns(
                r,
                tracked,
                is_public,
                text_patterns,
                text_file_globs,
            ),
            lambda r: _check_stale_rename_refs(r, tracked),
            lambda r: _check_unused_workspace_deps(r),
            lambda r: _check_tracked_ignored(r),
            lambda r: _check_local_path_deps(r, tracked),
            lambda r: _check_history_bloat(r, tracked),
        ):
            try:
                finding = check_fn(repo)
            except Exception as exc:
                errors.append(f"{repo}: check error: {exc}")
                continue
            if finding is not None:
                result.findings.append(finding)
                total_findings += 1

        results.append(result)

    # Sort: most findings first, then by path
    results.sort(key=lambda r: (-len(r.findings), r.repo_path))

    severity_counts: dict[str, int] = {"medium": 0, "low": 0}
    for r in results:
        for f in r.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {
            "dev_root": str(root),
            "repos_scanned": len(repos),
            "max_depth": max_depth,
            "exclude_repo_globs": globs,
        },
        "summary": {
            "repos_with_findings": sum(1 for r in results if r.findings),
            "total_findings": total_findings,
            "severity_counts": severity_counts,
        },
        "repos": [
            {
                "repo_path": r.repo_path,
                "is_public": r.is_public,
                "findings": [
                    {
                        "check": f.check,
                        "severity": f.severity,
                        "message": f.message,
                        "files": f.files,
                    }
                    for f in r.findings
                ],
            }
            for r in results
            if r.findings
        ][:200],
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
