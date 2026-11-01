"""Repo hygiene sweep: detect structural problems across local git repos.

Checks each repo for scattered doc dirs, committed generated data, hardcoded
absolute paths in shell scripts, stale .gitkeep files, tracked editor/cache
directories, internal documents in public repos, stale rename references,
declaration-only [workspace.dependencies] entries, and build inputs that exist
on disk but are not tracked by git.
"""

from __future__ import annotations

import ast
import configparser
import difflib
import fnmatch
import json
import os
import posixpath
import re
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import dotenv_values

from devguard.sweeps._common import contained_file, iter_git_repos
from devguard.sweeps._common import default_dev_root as _default_dev_root
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


class _GitInspectionError(RuntimeError):
    """A bounded diagnostic without subprocess output or repository paths."""


def _git_output(
    repo: Path, args: list[str], *, timeout: int = 60, input_data: bytes | None = None
) -> bytes:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            input=input_data,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise _GitInspectionError(f"git {args[0]} inspection timed out") from None
    except OSError:
        raise _GitInspectionError(f"git {args[0]} inspection could not run") from None
    if proc.returncode != 0:
        raise _GitInspectionError(f"git {args[0]} inspection failed (exit {proc.returncode})")
    return proc.stdout


def _git_ls_files(repo: Path) -> list[str]:
    """Return tracked paths, preserving inspection failures for the sweep report."""
    out = _git_output(repo, ["ls-files", "-z"]).decode("utf-8", errors="replace")
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
# A web URL's path is not a local path. Keep query/fragment values and
# surrounding text visible: they can still contain real home directories.
_HTTP_URL_PATH_RE = re.compile(
    r"""\bhttps?://[^/\s"'<>`\\?#]+/[^\s"'<>`\\?#(),;]*""", re.IGNORECASE
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
        if (
            path.is_symlink()
            or not contained_file(path, repo)
            or path.stat().st_size > _TEXT_SCAN_MAX_BYTES
        ):
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
            line = _HTTP_URL_PATH_RE.sub(" ", line)
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
    """I: Tracked files matched by repository .gitignore files, not user excludes."""
    output = _git_output(
        repo, ["ls-files", "-z", "--cached", "--ignored", "--exclude-per-directory=.gitignore"]
    )
    files = [p for p in output.decode("utf-8", errors="replace").split("\0") if p]
    if not files:
        return None
    secret_like = [f for f in files if _SECRET_LIKE_NAME_RE.match(Path(f).name)]
    return HygieneFinding(
        repo_path=str(repo),
        check="tracked_but_ignored",
        severity="medium" if secret_like else "low",
        message=(
            f"{len(files)} tracked file(s) match the repo's .gitignore rules"
            + (f", {len(secret_like)} with secret-like names" if secret_like else "")
            + " -- untrack them (git rm --cached) or narrow the rule."
        ),
        files=(secret_like + [f for f in files if f not in secret_like])[:20],
    )


_BACKUP_RE = re.compile(r"\.(?:bak|orig|rej|swp|tmp)$|~$")
_OS_JUNK = frozenset({".DS_Store", "Thumbs.db"})
_SESSION_LOG_RE = re.compile(
    r"(?:^|/)(?:progress|session|review-status|handoff|scratch)(?:[-_](?:log|notes))?\.md$",
    re.IGNORECASE,
)
_BUILT_DOC_RE = re.compile(r"(?:^|/)(?:typst-output|_site|book/html|target/doc|build/html)/")
_BUNDLE_SUFFIXES = (".js", ".mjs", ".css")


def _looks_bundled(repo: Path, rel: str) -> bool:
    text = _tracked_text(repo, rel)
    if text is None:
        # _tracked_text skips files over 1 MiB; a source file that big is a bundle.
        path = repo / rel
        return (
            path.is_file() and not path.is_symlink() and path.stat().st_size > _TEXT_SCAN_MAX_BYTES
        )
    return "sourceMappingURL=" in text or any(len(line) > 5000 for line in text.splitlines())


def _check_stray_files(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """L: Backups, OS junk, case collisions, agent session logs, bundles, built docs."""
    groups: dict[str, list[str]] = {}

    def add(kind: str, rel: str) -> None:
        groups.setdefault(kind, []).append(rel)

    seen_lower: dict[str, str] = {}
    for rel in tracked:
        name = Path(rel).name
        if _BACKUP_RE.search(name):
            add("backup", rel)
        if name in _OS_JUNK:
            add("os_junk", rel)
        if _SESSION_LOG_RE.search(rel):
            add("session_log", rel)
        if _BUILT_DOC_RE.search(rel):
            add("built_docs", rel.split("/", 1)[0] + "/...")
        if name.endswith(_BUNDLE_SUFFIXES) and _looks_bundled(repo, rel):
            add("bundled", rel)
        # Compare every parent directory too: Scripts/a vs scripts/b collide on
        # case-insensitive filesystems even though the files differ.
        parts = rel.split("/")
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            other = seen_lower.setdefault(prefix.lower(), prefix)
            if other != prefix:
                add("case_collision", f"{other} vs {prefix}")
    pkg = repo / "package.json"
    if (
        "package.json" in tracked
        and contained_file(pkg, repo)
        and "obfuscat" in pkg.read_text(errors="replace")
    ):
        add("obfuscated_build", "package.json")
    if not groups:
        return None
    files = [f"{kind}: {rel}" for kind, rels in groups.items() for rel in sorted(set(rels))]
    return HygieneFinding(
        repo_path=str(repo),
        check="stray_files",
        severity="low",
        message="Stray tracked files: "
        + ", ".join(f"{len(set(v))} {k}" for k, v in groups.items())
        + ".",
        files=files[:20],
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
    revs = _git_output(repo, ["rev-list", "--objects", "--all"], timeout=120)
    if not revs:
        return None
    sizes = _git_output(
        repo,
        ["cat-file", "--batch-check=%(objecttype) %(objectsize) %(rest)"],
        timeout=120,
        input_data=revs,
    )
    in_head = set(tracked)
    big: dict[str, int] = {}
    artifacts: set[str] = set()
    for line in sizes.decode("utf-8", errors="replace").splitlines():
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
        if not contained_file(repo / rel, repo):
            continue
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


_REF_MAX_FINDINGS = 20
_REF_MAX_CANDIDATES = 400
_REF_DIR_MAX_FILES = 200
_REF_SOURCE_NAMES: frozenset[str] = frozenset(
    {"build.rs", "Cargo.toml", "pyproject.toml", "setup.py", "setup.cfg"}
)
# Generated trees: a reference into them is output, not an input a clone needs.
_REF_SKIP_PARTS: frozenset[str] = frozenset(
    {"target", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".git", ".tox"}
)
_BUILD_INCLUDE_RE = re.compile(r"""\.include\s*\(\s*"([^"]+)"\s*\)""")
_RERUN_IF_CHANGED_RE = re.compile(r"""rerun-if-changed\s*=\s*(?:"([^"]+)"|([^\s"\\]+))""")
_INCLUDE_MACRO_RE = re.compile(r"""include_(?:str|bytes)!\s*\(\s*r?#?"([^"]+)"#?\s*\)""")
_CARGO_PATH_RE = re.compile(r"""^\s*path\s*=\s*"([^"]+)"\s*$""", re.MULTILINE)
# Rust doc examples quote real references; a commented-out path is not an input.
_COMMENT_LINE_RE = re.compile(r"^\s*(?://|/\*|\*)")


@dataclass(frozen=True)
class _RequiredRef:
    """One build/test input named by a tracked file."""

    kind: str
    base_dir: str
    target: str


def _normalize_reference(base_dir: str, target: str) -> str | None:
    """Resolve a reference target to a repo-relative POSIX path, else None.

    Absolute paths, `..` escapes, env placeholders and format strings are
    dropped: they are not a fixed input a clone can be checked for.
    """
    target = target.strip()
    if not target or "://" in target:
        return None
    if any(token in target for token in ("$", "{", "}", "%", "\\", "~")):
        return None
    if target.startswith("/") or re.match(r"^[A-Za-z]:", target):
        return None
    rel = posixpath.normpath(posixpath.join(base_dir, target))
    if rel in (".", "..") or rel.startswith("../"):
        return None
    return rel


def _string_list(value: Any) -> list[str]:
    """Coerce a string or a sequence of strings into a string list."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, str)]
    return []


def _package_pattern_refs(kind: str, packages: Any) -> list[_RequiredRef]:
    """setuptools package_data/data_files mappings: package -> patterns."""
    if not isinstance(packages, dict):
        return []
    refs: list[_RequiredRef] = []
    for pkg, patterns in packages.items():
        if not isinstance(pkg, str):
            continue
        base = pkg.replace(".", "/")
        for pattern in _string_list(patterns):
            if pattern.strip():
                refs.append(_RequiredRef(kind, base, pattern))
    return refs


def _pyproject_data_refs(text: str) -> list[_RequiredRef]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    tool = data.get("tool")
    setuptools = tool.get("setuptools") if isinstance(tool, dict) else None
    if not isinstance(setuptools, dict):
        return []
    refs = _package_pattern_refs("package_data", setuptools.get("package-data"))
    refs += _package_pattern_refs("data_files", setuptools.get("data-files"))
    return refs


def _setup_py_data_refs(text: str) -> list[_RequiredRef]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    refs: list[_RequiredRef] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg not in ("data_files", "package_data"):
                continue
            try:
                value = ast.literal_eval(kw.value)
            except (ValueError, SyntaxError, TypeError):
                continue
            if kw.arg == "package_data":
                refs.extend(_package_pattern_refs("package_data", value))
                continue
            if isinstance(value, dict):
                entries: Any = list(value.items())
            elif isinstance(value, (list, tuple)):
                entries = value
            else:
                continue
            for entry in entries:
                if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                    continue
                for pattern in _string_list(entry[1]):
                    refs.append(_RequiredRef("data_files", "", pattern))
    return refs


def _setup_cfg_data_refs(text: str) -> list[_RequiredRef]:
    parser = configparser.ConfigParser()
    try:
        parser.read_string(text)
    except configparser.Error:
        return []
    refs: list[_RequiredRef] = []
    for section, kind, dotted in (
        ("options.package_data", "package_data", True),
        ("options.data_files", "data_files", False),
    ):
        if not parser.has_section(section):
            continue
        for pkg, value in parser.items(section):
            base = pkg.replace(".", "/") if dotted else ""
            for pattern in (item for item in re.split(r"[\s,]+", value) if item):
                refs.append(_RequiredRef(kind, base, pattern))
    return refs


def _file_references(rel: str, text: str) -> list[_RequiredRef]:
    """Build inputs one tracked reference source names."""
    base_dir = posixpath.dirname(rel)
    name = posixpath.basename(rel)
    if name.endswith(".rs"):
        # Doc comments quote sample paths; they are not build inputs.
        code = "\n".join(line for line in text.splitlines() if not _COMMENT_LINE_RE.match(line))
        refs = [
            _RequiredRef("include", base_dir, m.group(1)) for m in _BUILD_INCLUDE_RE.finditer(code)
        ]
        refs += [
            _RequiredRef("rerun-if-changed", base_dir, m.group(1) or m.group(2))
            for m in _RERUN_IF_CHANGED_RE.finditer(code)
        ]
        refs += [
            _RequiredRef("include_str!/include_bytes!", base_dir, m.group(1))
            for m in _INCLUDE_MACRO_RE.finditer(code)
        ]
        return refs
    if name == "Cargo.toml":
        return [
            _RequiredRef("Cargo.toml path =", base_dir, m.group(1))
            for m in _CARGO_PATH_RE.finditer(text)
        ]
    if name == "pyproject.toml":
        return _pyproject_data_refs(text)
    if name == "setup.py":
        return _setup_py_data_refs(text)
    if name == "setup.cfg":
        return _setup_cfg_data_refs(text)
    return []


def _is_reference_source(rel: str) -> bool:
    return rel.endswith(".rs") or posixpath.basename(rel) in _REF_SOURCE_NAMES


def _referenced_dir_files(repo: Path, rel_dir: str) -> list[str]:
    """Bounded list of regular files inside a referenced directory."""
    found: list[str] = []
    stack = [repo / rel_dir]
    while stack and len(found) < _REF_DIR_MAX_FILES:
        try:
            children = sorted(stack.pop().iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_symlink():
                continue
            if child.is_dir():
                if child.name in _REF_SKIP_PARTS or child.name.startswith("."):
                    continue
                stack.append(child)
            elif contained_file(child, repo):
                found.append(child.relative_to(repo).as_posix())
                if len(found) >= _REF_DIR_MAX_FILES:
                    break
    return sorted(found)


def _expand_glob(repo: Path, pattern: str) -> list[str]:
    hits: list[str] = []
    try:
        for path in repo.glob(pattern):
            if len(hits) >= _REF_DIR_MAX_FILES:
                break
            if path.is_symlink() or not contained_file(path, repo):
                continue
            hits.append(path.relative_to(repo).as_posix())
    except (ValueError, OSError):
        return []
    return sorted(hits)


def _untracked_of(repo: Path, rels: list[str]) -> set[str]:
    """Of *rels*, the ones git does not track (one batched ls-files call)."""
    if not rels:
        return set()
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "-z", "--error-unmatch", "--", *rels],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        raise _GitInspectionError("git ls-files inspection timed out") from None
    except OSError:
        raise _GitInspectionError("git ls-files inspection could not run") from None
    if proc.returncode >= 128:
        raise _GitInspectionError(f"git ls-files inspection failed (exit {proc.returncode})")
    matched = {p for p in proc.stdout.decode("utf-8", errors="replace").split("\0") if p}
    return {rel for rel in rels if rel not in matched}


def _ignore_source(repo: Path, rel: str) -> str | None:
    """The ignore rule that would skip *rel*, as `source:line:pattern`."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "check-ignore", "-v", "--", rel],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    lines = proc.stdout.decode("utf-8", errors="replace").splitlines()
    if not lines:
        return None
    # `git check-ignore -v` prints `<source>:<line>:<pattern>\t<path>`.
    source, _, rest = lines[0].split("\t")[0].partition(":")
    lineno, _, pattern = rest.partition(":")
    home = str(Path.home())
    if source.startswith(home + os.sep):
        source = "~" + source[len(home) :]
    return f"{source}:{lineno}:{pattern}"


def _check_required_file_untracked(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """M: Files a build script or manifest reads, present on disk but untracked.

    A gitignored `vendor/` makes `git add -A` skip a header that `build.rs`
    includes: the local build passes and every fresh clone or CI run fails.
    References come from build scripts (`include(...)`, `rerun-if-changed`),
    `include_str!`/`include_bytes!`, `Cargo.toml` `path =`, and setuptools
    `data_files`/`package_data`.
    """
    candidates: dict[str, tuple[str, str]] = {}

    def add_candidate(candidate: str, referrer: str, kind: str) -> None:
        if len(candidates) < _REF_MAX_CANDIDATES:
            candidates.setdefault(candidate, (referrer, kind))

    for referrer in tracked:
        if not _is_reference_source(referrer):
            continue
        text = _tracked_text(repo, referrer)
        if text is None:
            continue
        for ref in _file_references(referrer, text):
            rel = _normalize_reference(ref.base_dir, ref.target)
            if rel is None or any(part in _REF_SKIP_PARTS for part in rel.split("/")):
                continue
            if any(ch in rel for ch in "*?["):
                for hit in _expand_glob(repo, rel):
                    add_candidate(hit, referrer, ref.kind)
                continue
            path = repo / rel
            if path.is_dir():
                if ref.kind == "Cargo.toml path =":
                    # A path dependency names a manifest, not a file inside.
                    manifest = posixpath.join(rel, "Cargo.toml")
                    if (repo / manifest).is_file():
                        add_candidate(manifest, referrer, ref.kind)
                    continue
                for hit in _referenced_dir_files(repo, rel):
                    add_candidate(hit, referrer, ref.kind)
            elif path.is_file():
                add_candidate(rel, referrer, ref.kind)

    untracked = _untracked_of(repo, list(candidates))
    if not untracked:
        return None

    files: list[str] = []
    ignored = False
    for rel, (referrer, kind) in candidates.items():
        if rel not in untracked:
            continue
        rule = _ignore_source(repo, rel)
        if rule is not None:
            ignored = True
            files.append(f"{rel} <- {referrer} ({kind}; ignored by {rule})")
        else:
            files.append(f"{rel} <- {referrer} ({kind})")
        if len(files) >= _REF_MAX_FINDINGS:
            break

    return HygieneFinding(
        repo_path=str(repo),
        check="required_file_untracked",
        severity="medium" if ignored else "low",
        message=(
            f"{len(files)} file(s) referenced by build scripts or manifests exist only in "
            "the working tree -- a fresh clone or CI build will not have them. "
            "`git add -f` them, or stop referencing them."
        ),
        files=files,
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
        if not contained_file(path, repo) or path.suffix.lower() in _TEXT_POLICY_BINARY_SUFFIXES:
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


def _check_crate_level_test_gates(repo: Path) -> HygieneFinding | None:
    """Flag Rust test files gated at crate level with `#![cfg(all(...))]`.

    Such a gate compiles the whole file to zero tests when any listed feature is
    off, so `cargo test` reports success having run nothing.
    """
    tests_dir = repo / "tests"
    if not tests_dir.is_dir():
        return None
    offenders: list[str] = []
    for path in sorted(tests_dir.rglob("*.rs")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        head = "\n".join(text.splitlines()[:20])
        if "#![cfg(all(" in head.replace(" ", ""):
            offenders.append(str(path.relative_to(repo)))
    if not offenders:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="crate_level_test_gate",
        severity="medium",
        message=(
            f"{len(offenders)} test file(s) gated with #![cfg(all(...))]: "
            "they compile to zero tests under a partial feature set"
        ),
        files=offenders[:10],
    )


def _check_ignored_tests_without_reason(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """Flag `#[ignore]` without a reason string.

    A bare `#[ignore]` removes a test from the suite with no explanation and no
    way to tell a queued row from an abandoned one.
    """
    offenders: list[str] = []
    for rel in tracked:
        if not rel.endswith(".rs"):
            continue
        path = repo / rel
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if stripped in ("#[ignore]", "#[ignore =]"):
                offenders.append(rel)
                break
    if not offenders:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="ignored_test_without_reason",
        severity="low",
        message=f"{len(offenders)} file(s) carry a bare #[ignore] with no reason",
        files=offenders[:10],
    )


# --- Cargo feature drift ----------------------------------------------------

_FEATURE_SCAN_MAX_BYTES = 512 * 1024
_FEATURE_SCAN_MAX_FILES = 400
_FEATURE_FINDING_CAP = 20

# A finding can be silenced at its source, but only with a stated reason. The
# reason is what separates "this is intentional" from "the author did not look":
# suppressing without one is not honoured, so a wipe of the pragma re-exposes the
# finding rather than hiding it behind an empty annotation.
_ALLOW_PRAGMA_RE = re.compile(
    r"devguard:\s*allow(?P<scope>-file)?\s+(?P<check>[a-z_]+)(?P<rest>.*)$", re.I
)
_ALLOW_REASON_RE = re.compile(r"reason\s*[:=]\s*(?P<reason>[^\n]*?)\s*(?:-->|\*/|$)", re.I)
_ALLOW_LINE_WINDOW = 6


def _allow_ranges(text: str) -> dict[str, list[tuple[int, int]]]:
    """Line ranges (0-based, inclusive) each check may ignore in *text*.

    `devguard: allow <check> reason: ...` covers the lines that follow it, so a
    note above one stale command excuses that command and nothing else.
    `devguard: allow-file <check> reason: ...` covers the whole file, for a
    document that is historical end to end. Both require a reason: an annotation
    without one is ignored, so deleting the reason re-exposes the finding instead
    of hiding it behind a bare pragma.
    """
    out: dict[str, list[tuple[int, int]]] = {}
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        match = _ALLOW_PRAGMA_RE.search(line)
        if match is None:
            continue
        reason = _ALLOW_REASON_RE.search(match.group("rest") or "")
        if reason is None or not reason.group("reason").strip():
            continue
        check = match.group("check").lower()
        if match.group("scope"):
            out.setdefault(check, []).append((0, len(lines)))
        else:
            out.setdefault(check, []).append((idx, idx + _ALLOW_LINE_WINDOW))
    return out


def _allowed(ranges: dict[str, list[tuple[int, int]]], check: str, lineno: int) -> bool:
    return any(start <= lineno <= end for start, end in ranges.get(check, ()))
# A feature value that means "whatever the manifest defaults to", not a name.
_FEATURE_VALUE_SKIP: frozenset[str] = frozenset({"default"})
_CARGO_FEATURES_RE = re.compile(
    r"""(?:--features(?:=|\s+)|-F(?:=|\s+))(?:"([^"]*)"|'([^']*)'|([^\s"'`]+))"""
)
# `cd subdir &&` or `working-directory:` set the package a command runs against.
_CD_RE = re.compile(r"""(?:^|&&|\bthen\s+)\s*cd\s+["']?([^\s&;"']+)""")
_MANIFEST_PATH_RE = re.compile(r"""--manifest-path(?:=|\s+)["']?([^\s"';]+)""")
_WORKING_DIR_RE = re.compile(r"""working-directory:\s*["']?([^\s"'}]+)""")
# `cargo run -p pkg --features x`: the flag names the package, not the cwd.
_PACKAGE_FLAG_RE = re.compile(r"""(?:^|\s)(?:-p|--package)(?:=|\s+)["']?([A-Za-z0-9_-]+)""")
_CFG_MODULE_RE = re.compile(
    r'^#\[cfg\(feature\s*=\s*"([^"]+)"\)\]\s*'
    r"(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*[;{]",
    re.M,
)
_CFG_ATTR_RE = re.compile(r"^\s*#\[cfg\(")
_FILE_CFG_RE = re.compile(r"^\s*#!\[cfg\(", re.M)
_VERSION_CORE_RE = re.compile(r"^[=~^]?\s*v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")
_INSTALL_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=\s*(\"[^\"]*\"|\{[^}]*\})\s*$")
_TOML_VERSION_RE = re.compile(r"""\bversion\s*=\s*"([^"]*)\"""")
_TOML_REMOTE_RE = re.compile(r"\b(?:path|git)\s*=")


@dataclass(frozen=True)
class _CargoPackage:
    """One `[package]` manifest and the features it defines."""

    manifest_rel: str
    dir_rel: str
    name: str
    features: frozenset[str]


def _cargo_packages(repo: Path) -> list[_CargoPackage]:
    """Every package manifest under *repo* with its declared feature names."""
    out: list[_CargoPackage] = []
    for rel in _find_cargo_manifests(repo):
        data = _parse_toml(repo / rel)
        if data is None:
            continue
        pkg = data.get("package")
        name = pkg.get("name") if isinstance(pkg, dict) else None
        if not isinstance(name, str):
            continue
        raw = data.get("features")
        declared = raw if isinstance(raw, dict) else {}
        features = {k for k in declared if isinstance(k, str)}
        # An optional dependency creates an implicit feature of the same name
        # unless some feature already names it as `dep:<name>`.
        explicit = {
            v.split("dep:", 1)[1]
            for values in declared.values()
            if isinstance(values, list)
            for v in values
            if isinstance(v, str) and v.startswith("dep:")
        }
        for table in _dep_tables(data):
            for dep, spec in table.items():
                if not isinstance(dep, str) or dep in explicit:
                    continue
                if isinstance(spec, dict) and spec.get("optional") is True:
                    features.add(dep)
        parent = str(Path(rel).parent)
        out.append(
            _CargoPackage(
                manifest_rel=rel,
                dir_rel="." if parent in ("", ".") else parent,
                name=name,
                features=frozenset(features),
            )
        )
    return out


def _known_features(packages: list[_CargoPackage]) -> frozenset[str]:
    """Union of features across the repo's packages.

    A feature name valid in one workspace member is valid on the command line,
    so the union only suppresses false positives.
    """
    return frozenset().union(*(p.features for p in packages)) if packages else frozenset()


def _package_for_dir(packages: list[_CargoPackage], dir_rel: str) -> _CargoPackage | None:
    best: _CargoPackage | None = None
    for pkg in packages:
        inside = pkg.dir_rel == "." or (
            dir_rel == pkg.dir_rel or dir_rel.startswith(pkg.dir_rel + "/")
        )
        if inside and (best is None or len(pkg.dir_rel) > len(best.dir_rel)):
            best = pkg
    return best


def _feature_command_files(repo: Path, tracked: list[str]) -> list[str]:
    """Bounded set of files that carry cargo invocations: CI, task runners, docs."""
    out: list[str] = []
    for rel in tracked:
        parts = Path(rel).parts
        name = posixpath.basename(rel).lower()
        is_workflow = (
            len(parts) >= 3
            and parts[0] == ".github"
            and parts[1] == "workflows"
            and name.endswith((".yml", ".yaml"))
        )
        is_runner = name in ("justfile", "makefile", "gnumakefile", "justfile.toml")
        is_doc = name.endswith(".md")
        if is_workflow or is_runner or is_doc:
            out.append(rel)
        if len(out) >= _FEATURE_SCAN_MAX_FILES:
            break
    return out


def _command_dir(repo: Path, rel: str, lines: list[str], lineno: int, cwd: str | None) -> str:
    """Best-effort working directory for the command on *lineno* (repo-relative)."""
    line = lines[lineno]
    match = _MANIFEST_PATH_RE.search(line)
    if match:
        cwd = str(Path(match.group(1)).parent)
    else:
        match = _CD_RE.search(line)
        if match:
            cwd = match.group(1)
        elif cwd is None:
            for back in range(lineno - 1, -1, -1):
                found = _WORKING_DIR_RE.search(lines[back])
                if found:
                    cwd = found.group(1)
                    break
    base = str(Path(rel).parent)
    base = "" if base in ("", ".") else base
    if not cwd or cwd.startswith("$"):
        return base or "."
    joined = posixpath.normpath(posixpath.join(base, cwd))
    if joined.startswith(".."):
        return base or "."
    return joined or "."


def _feature_values(match: re.Match[str]) -> list[str]:
    raw = next((g for g in match.groups() if g is not None), "")
    return [v for v in re.split(r"[,\s]+", raw) if v]


def _check_unknown_features(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """CI or documented `cargo --features` naming a feature no manifest defines.

    A renamed feature leaves every job that still asks for the old name failing
    before compilation, so the workflow edit and the rename must land together.
    """
    packages = _cargo_packages(repo)
    if not packages:
        return None
    known = _known_features(packages)
    if not known:
        return None

    hits: list[str] = []
    seen: set[tuple[str, int, str]] = set()
    for rel in _feature_command_files(repo, tracked):
        path = repo / rel
        if not contained_file(path, repo):
            continue
        try:
            if path.stat().st_size > _FEATURE_SCAN_MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        allow = _allow_ranges(text)
        cwd: str | None = None
        for lineno, line in enumerate(lines):
            if _allowed(allow, "feature_name_unknown", lineno):
                continue
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue
            if "cargo" not in line:
                continue
            cwd = _command_dir(repo, rel, lines, lineno, cwd)
            # A command may name its packages explicitly, which beats the cwd.
            # Several `-p` flags select several packages; the feature must exist
            # in at least one of them, so their features union.
            pkg_flags = _PACKAGE_FLAG_RE.findall(line)
            if pkg_flags:
                selected = [p for p in packages if p.name in pkg_flags]
                allowed = frozenset().union(*(p.features for p in selected)) if selected else known
            else:
                local = _package_for_dir(packages, cwd)
                allowed = local.features if local is not None else known
            for match in _CARGO_FEATURES_RE.finditer(line):
                for value in _feature_values(match):
                    if value in _FEATURE_VALUE_SKIP or "/" in value or value.startswith("dep:"):
                        continue
                    if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
                        continue
                    # CI template expressions (`${{ matrix.features }}`) name a
                    # matrix axis, not a feature the manifest must define.
                    if "{{" in value or value.startswith("$") or value.startswith("matrix."):
                        continue
                    if value in allowed:
                        continue
                    key = (rel, lineno + 1, value)
                    if key in seen:
                        continue
                    seen.add(key)
                    nearest = difflib.get_close_matches(value, sorted(known), n=1, cutoff=0.0)
                    hint = f" (nearest: {nearest[0]})" if nearest else ""
                    hits.append(f"{rel}:{lineno + 1}: {value}{hint}")
                    if len(hits) >= _FEATURE_FINDING_CAP:
                        break
                if len(hits) >= _FEATURE_FINDING_CAP:
                    break
            if len(hits) >= _FEATURE_FINDING_CAP:
                break

    if not hits:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="feature_name_unknown",
        severity="medium",
        message=(
            f"{len(hits)} cargo feature reference(s) name a feature no manifest in the "
            "repo defines -- those jobs fail before compiling."
        ),
        files=hits,
    )


def _cfg_gated_ranges(lines: list[str]) -> list[tuple[int, int]]:
    """Line ranges covered by a `#[cfg(...)]` attribute on the following item.

    Attributes may span lines (`#[cfg(any(\n feature = "a",\n))]`), so the
    parenthesis depth decides where the attribute ends and the item begins.
    """
    ranges: list[tuple[int, int]] = []
    total = len(lines)
    for idx, line in enumerate(lines):
        if not _CFG_ATTR_RE.match(line):
            continue
        item = idx
        parens = 0
        while item < total:
            parens += lines[item].count("(") - lines[item].count(")")
            item += 1
            if parens <= 0:
                break
        while item < total:
            probe = lines[item].strip()
            if not probe or probe.startswith("//"):
                item += 1
                continue
            if probe.startswith("#["):
                parens = lines[item].count("(") - lines[item].count(")")
                item += 1
                while parens > 0 and item < total:
                    parens += lines[item].count("(") - lines[item].count(")")
                    item += 1
                continue
            break
        if item >= total:
            continue
        start, end = item, item
        depth = lines[item].count("{") - lines[item].count("}")
        if depth > 0:
            cursor = item + 1
            while cursor < total and depth > 0:
                depth += lines[cursor].count("{") - lines[cursor].count("}")
                end = cursor
                cursor += 1
        ranges.append((start, end))
    return ranges


def _target_required_features(
    manifest: dict[str, Any], kind: str, name: str, rel: str
) -> frozenset[str]:
    """`required-features` declared for one [[test]]/[[example]] target."""
    for entry in manifest.get(kind, []) if isinstance(manifest.get(kind), list) else []:
        if not isinstance(entry, dict):
            continue
        if entry.get("name") != name and entry.get("path") != rel:
            continue
        raw = entry.get("required-features")
        if isinstance(raw, list):
            return frozenset(v for v in raw if isinstance(v, str))
    return frozenset()


def _test_target_name(rel: str) -> str | None:
    """Target name for a Rust test/example entry point, or None for a submodule."""
    parts = Path(rel).parts
    if len(parts) < 2 or parts[0] not in ("tests", "examples"):
        return None
    tail = parts[1:]
    if len(tail) == 1 and tail[0].endswith(".rs"):
        return tail[0][:-3]
    if len(tail) == 2 and tail[1] == "main.rs":
        return tail[0]
    return None


def _check_test_target_missing_gate(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """A test/example that uses a feature-gated module without gating itself.

    `#[cfg(feature = "x")] pub mod y;` in the crate root means the module only
    exists with that feature. A target that names it and carries no `cfg` gate
    fails to compile in every feature lane that omits it.
    """
    packages = _cargo_packages(repo)
    if not packages:
        return None

    graders: list[str] = []
    for pkg in packages:
        lib = (
            repo / pkg.dir_rel / "src" / "lib.rs" if pkg.dir_rel != "." else repo / "src" / "lib.rs"
        )
        if not contained_file(lib, repo):
            continue
        try:
            lib_text = lib.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        gated = {module: feature for feature, module in _CFG_MODULE_RE.findall(lib_text)}
        if not gated:
            continue
        manifest = _parse_toml(repo / pkg.manifest_rel) or {}
        crate_name = pkg.name.replace("-", "_")
        crate_re = re.compile(rf"\b{re.escape(crate_name)}::([A-Za-z_][A-Za-z0-9_]*)")
        for rel in tracked:
            name = _test_target_name(rel)
            if name is None:
                continue
            if pkg.dir_rel != "." and not rel.startswith(pkg.dir_rel + "/"):
                continue
            path = repo / rel
            if not contained_file(path, repo):
                continue
            try:
                if path.stat().st_size > _FEATURE_SCAN_MAX_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _FILE_CFG_RE.search(text):
                continue
            lines = text.splitlines()
            allow = _allow_ranges(text)
            gated_ranges = _cfg_gated_ranges(lines)
            kind = "test" if rel.startswith("tests/") else "example"
            required = _target_required_features(manifest, kind, name, rel)
            for lineno, line in enumerate(lines):
                if _allowed(allow, "test_target_missing_gate", lineno):
                    continue
                stripped = line.lstrip()
                if not stripped or stripped.startswith("//"):
                    continue
                match = crate_re.search(line)
                if not match:
                    continue
                module = match.group(1)
                feature = gated.get(module)
                if feature is None:
                    continue
                if feature in required:
                    continue
                if any(start <= lineno <= end for start, end in gated_ranges):
                    continue
                graders.append(f"{rel}: {crate_name}::{module} needs feature {feature!r}")
                break

    if not graders:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="test_target_missing_gate",
        severity="medium",
        message=(
            f"{len(graders)} test/example target(s) use a feature-gated module without a "
            "cfg gate or required-features -- they break every lane that omits it."
        ),
        files=graders[:_FEATURE_FINDING_CAP],
    )


def _check_readme_install_version(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """A README install pin that disagrees with the manifest version.

    A stale pin sends readers to docs and an API that the release no longer has.
    Only the crate's own manifest counts, and only exact triples are compared:
    `crate = "1"` is a valid range, not drift.
    """
    hits: list[str] = []
    seen: set[tuple[str, str]] = set()
    for rel in tracked:
        name = posixpath.basename(rel).lower()
        if name != "readme.md":
            continue
        readme = repo / rel
        base_rel = str(Path(rel).parent)
        base = repo if base_rel in ("", ".") else repo / base_rel
        manifest_path = base / "Cargo.toml"
        if not contained_file(manifest_path, repo) or not manifest_path.is_file():
            continue
        manifest = _parse_toml(manifest_path)
        if manifest is None:
            continue
        pkg = manifest.get("package")
        if not isinstance(pkg, dict):
            continue
        crate = pkg.get("name")
        version = pkg.get("version")
        if not isinstance(crate, str) or not isinstance(version, str):
            continue
        want = _VERSION_CORE_RE.match(version)
        if not want:
            continue
        manifest_rel = str(manifest_path.relative_to(repo))
        try:
            text = readme.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        allow = _allow_ranges(text)
        for lineno, line in enumerate(text.splitlines(), 1):
            if _allowed(allow, "readme_install_version", lineno - 1):
                continue
            match = _INSTALL_LINE_RE.match(line)
            if not match or match.group(1) != crate:
                continue
            spec = match.group(2)
            if spec.startswith("{"):
                if _TOML_REMOTE_RE.search(spec):
                    continue
                pinned = _TOML_VERSION_RE.search(spec)
                if not pinned:
                    continue
            else:
                pinned = re.match(r'"([^"]*)"', spec)
                if not pinned:
                    continue
            got = _VERSION_CORE_RE.match(pinned.group(1).strip())
            if got is None:
                continue
            if got.groups() == want.groups():
                continue
            key = (rel, str(lineno))
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                f"{rel}:{lineno}: README pins {pinned.group(1)}, "
                f"manifest {manifest_rel} ships {version}"
            )
    if not hits:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="readme_install_version",
        severity="low",
        message=(
            f"{len(hits)} README install pin(s) disagree with the crate's manifest "
            "version -- readers land on docs for an API the release lacks."
        ),
        files=hits[:_FEATURE_FINDING_CAP],
    )


def _check_stale_rename_refs(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """G: Cargo.toml name differs from directory name; old name still appears as env var prefix."""
    cargo = repo / "Cargo.toml"
    if not contained_file(cargo, repo):
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
        if not contained_file(path, repo):
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
        if contained_file(manifest, repo):
            found.append(str(manifest.relative_to(repo)))
        if depth >= max_depth:
            continue
        try:
            for child in cur.iterdir():
                if child.is_symlink() or not child.is_dir():
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
        data = (
            (_parse_toml(d / "Cargo.toml") if contained_file(d / "Cargo.toml", ws_dir) else None)
            if d != ws_dir
            else root_data
        )
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
        except _GitInspectionError as exc:
            errors.append(str(exc))
            continue
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
            lambda r: _check_crate_level_test_gates(r),
            lambda r: _check_ignored_tests_without_reason(r, tracked),
            lambda r: _check_unknown_features(r, tracked),
            lambda r: _check_test_target_missing_gate(r, tracked),
            lambda r: _check_readme_install_version(r, tracked),
            lambda r: _check_unused_workspace_deps(r),
            lambda r: _check_tracked_ignored(r),
            lambda r: _check_local_path_deps(r, tracked),
            lambda r: _check_history_bloat(r, tracked),
            lambda r: _check_required_file_untracked(r, tracked),
            lambda r: _check_stray_files(r, tracked),
        ):
            try:
                finding = check_fn(repo)
            except _GitInspectionError as exc:
                errors.append(str(exc))
                continue
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
