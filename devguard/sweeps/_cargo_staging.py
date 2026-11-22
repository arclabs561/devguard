"""Find multi-package publish checks whose Cargo staging directory may be reused.

Follow literal shell commands in GitHub Actions run steps and the local scripts
they invoke. Never execute a command or expand paths outside the checkout.
"""

from __future__ import annotations

import fnmatch
import re
import shlex
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from itertools import count
from pathlib import Path

import yaml  # type: ignore[import-untyped]

# Recognize a directory actually allocated by mktemp, including Anno's
# `$(mktemp -d "${TMPDIR:-/tmp}/name.XXXXXX")`. A name under /tmp alone
# gives no freshness guarantee. Preserve single-quoted literals as literals.
_TEMP = re.compile(r'\$\(mktemp\s+(?:-d|--directory)(?:\s+["\w./${}:=-]+)?\)')
_VAR = re.compile(r"\$(?:\{(\w+)\}|([a-zA-Z_]\w*))")
_ASSIGN = re.compile(r"^([a-zA-Z_]\w*)=(.*)$")


def _inside(repo: Path, cwd: Path, path: str) -> Path | None:
    try:
        resolved = (cwd / path).resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    return resolved if resolved.is_relative_to(repo) else None


def _options(args: list[str], *names: str) -> list[str]:
    values = []
    for i, arg in enumerate(args):
        key, sep, value = arg.partition("=")
        if key in names:
            if sep:
                values.append(value)
            elif i + 1 < len(args):
                values.append(args[i + 1])
        elif "-p" in names and arg.startswith("-p") and len(arg) > 2:
            values.append(arg[2:])
    return values


def _manifest_data(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text())
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return {}


def _path_dependencies(config: dict, workspace: dict, root: Path, member: Path) -> Iterator[Path]:
    # Cargo implicitly adds in-tree path dependencies to the workspace,
    # including platform-specific, development, and build dependencies.
    targets = config.get("target", {})
    tables = [config, *(targets.values() if isinstance(targets, dict) else [])]
    for table in tables:
        if not isinstance(table, dict):
            continue
        for kind in (
            "dependencies",
            "dev-dependencies",
            "build-dependencies",
            "dev_dependencies",
            "build_dependencies",
        ):
            dependencies = table.get(kind, {})
            if not isinstance(dependencies, dict):
                continue
            for alias, spec in dependencies.items():
                if not isinstance(spec, dict):
                    continue
                base = member
                if spec.get("workspace") is True:
                    inherited = workspace.get("dependencies", {})
                    spec = inherited.get(alias) if isinstance(inherited, dict) else None
                    base = root
                if isinstance(spec, dict) and isinstance(spec.get("path"), str):
                    yield base / spec["path"] / "Cargo.toml"


def _selected_packages(repo: Path, cwd: Path, args: list[str]) -> frozenset[Path]:
    if not cwd.is_dir():
        return frozenset()
    packages = set(_options(args, "-p", "--package"))
    explicit = _options(args, "--manifest-path")
    if explicit:
        manifest = _inside(repo, cwd, explicit[-1])
    else:
        manifest = next(
            (
                d / "Cargo.toml"
                for d in (cwd, *cwd.parents)
                if d.is_relative_to(repo) and (d / "Cargo.toml").is_file()
            ),
            None,
        )
        if manifest:
            manifest = _inside(repo, cwd, str(manifest))
    if not manifest:
        return frozenset()
    config = _manifest_data(manifest)
    workspace = config.get("workspace")
    root_name = config.get("package", {}).get("name")
    whole = "--workspace" in args or "--all" in args
    if not isinstance(workspace, dict):
        if not root_name or (packages and packages != {root_name}) or whole:
            return frozenset()
        return frozenset([manifest])

    root = manifest.parent
    defaults = (
        None
        if whole or packages
        else workspace.get("default-members", ["."] if root_name else None)
    )
    if defaults is None:
        patterns = workspace.get("members", [])
        pending = [manifest] if root_name else []
    else:
        patterns = defaults
        pending = []
    for pattern in patterns:
        if (
            not isinstance(pattern, str)
            or Path(pattern).is_absolute()
            or ".." in Path(pattern).parts
        ):
            return frozenset()
        pending.extend(root.glob(f"{pattern}/Cargo.toml"))
    selected: set[Path] = set()
    matched: set[str] = set()
    seen: set[Path] = set()
    excluded = _options(args, "--exclude")
    while pending:
        member = pending.pop().resolve()
        if member in seen or not member.is_relative_to(root):
            continue
        seen.add(member)
        relative = member.parent.relative_to(root).as_posix()
        if any(fnmatch.fnmatchcase(relative, pat) for pat in workspace.get("exclude", [])):
            continue
        info = _manifest_data(member)
        if not info:
            return frozenset()
        if defaults is None:
            pending.extend(_path_dependencies(info, workspace, root, member.parent))
        name = info.get("package", {}).get("name")
        if not name or any(fnmatch.fnmatchcase(name, pat) for pat in excluded):
            continue
        matches = {pat for pat in packages if fnmatch.fnmatchcase(name, pat)}
        if not packages or matches:
            selected.add(member)
            matched.update(matches)
    return frozenset(selected) if matched == packages else frozenset()


@dataclass(frozen=True)
class StagingRisk:
    source: str
    line: int
    workflow_step: str


@dataclass(frozen=True)
class PublishStep:
    workflow: str
    location: str
    oidc: bool
    dry_run: bool
    packages: frozenset[Path]
    staging_risk: StagingRisk | None


def _commands(body: str, allocations: Iterator[int]) -> Iterator[tuple[int, list[str]]]:
    # Shell punctuation is split by shlex only outside quotes. The replacement
    # token keeps whitespace inside a literal mktemp expression together.
    logical = ""
    for number, raw in enumerate(body.splitlines(), start=1):
        if not logical:
            start = number
        if raw.endswith("\\"):
            logical += raw[:-1]
            continue
        line = logical + raw
        logical = ""
        line = re.sub(r"'[^']*'", lambda m: m[0].replace("$", "\x01"), line)
        line = _TEMP.sub(lambda _: f"\0mktemp:{next(allocations)}/", line)
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        try:
            words = list(lexer)
        except ValueError:
            continue
        command: list[str] = []
        for token in [*words, ";"]:
            if token in {";", "&&", "||", "|", "&"}:
                if command:
                    yield start, command
                command = []
            else:
                command.append(token)


def _scan(
    repo: Path,
    cwd: Path,
    body: str,
    source: str,
    step: str,
    env: dict[str, str],
    used: set[str],
    seen: set[Path],
    allocations: Iterator[int],
) -> Iterator[tuple[bool, frozenset[Path], StagingRisk | None]]:
    exported = set(env)
    for line, tokens in _commands(body, allocations):
        tokens = list(tokens)
        is_export = tokens[0] == "export"
        assigned = set()
        while tokens and tokens[0] in {
            "if",
            "then",
            "elif",
            "else",
            "!",
            "env",
            "export",
            "command",
        }:
            tokens.pop(0)
        values = env.copy()
        while tokens and (assignment := _ASSIGN.match(tokens[0])):
            tokens.pop(0)
            key, raw = assignment.groups()
            values[key] = _VAR.sub(lambda m: values.get(m[1] or m[2], m[0]), raw)
            assigned.add(key)
        if is_export:
            exported.update(assigned)
            exported.update(key for key in tokens if key.isidentifier())
        if not tokens:
            env.update(values)
            continue
        executable, *args = tokens
        if executable == "unset":
            for key in args:
                env.pop(key, None)
                exported.discard(key)
        if executable == "cd" and args:
            directory = _inside(repo, cwd, args[0])
            if directory is None:
                return
            cwd = directory
        if executable in {"sh", "bash"} and args:
            executable = args[0]
        if "/" in executable or executable.endswith(".sh"):
            script = _inside(repo, cwd, executable)
            if script and script not in seen and len(seen) < 5 and script.is_file():
                try:
                    script_body = script.read_text(encoding="utf-8")
                except (UnicodeError, OSError):
                    continue
                yield from _scan(
                    repo,
                    cwd,
                    script_body,
                    str(script.relative_to(repo)),
                    step,
                    {key: values[key] for key in exported | assigned if key in values},
                    used,
                    seen | {script},
                    allocations,
                )
        if executable != "cargo":
            continue
        if args and args[0].startswith("+"):
            args = args[1:]
        if args[:1] != ["publish"]:
            continue
        dry_run = "--dry-run" in args
        packages = _selected_packages(repo, cwd, args)
        if "--no-verify" in args and dry_run:
            # Cargo prepares the package without verifying the unpacked crate.
            yield True, frozenset(), None
            continue
        multi = len(packages) > 1 or len(set(_options(args, "-p", "--package"))) > 1
        if not dry_run or not multi:
            yield dry_run, packages, None
            continue
        inherited = (
            values.get("CARGO_TARGET_DIR", "") if "CARGO_TARGET_DIR" in exported | assigned else ""
        )
        target = (_options(args, "--target-dir") or [inherited])[-1]
        target = _VAR.sub(lambda m: values.get(m[1] or m[2], m[0]), target)
        # A repeated check with the same allocated directory can also be stale.
        risk = None
        if not target.startswith("\0mktemp:") or ".." in target.split("/") or target in used:
            risk = StagingRisk(source, line, step)
        used.add(target)
        yield dry_run, packages, risk


def publish_steps(repo: Path, workflows: list[tuple[str, str]]) -> Iterator[PublishStep]:
    repo = repo.resolve()
    for name, text in workflows:
        if "run:" not in text and "uses:" not in text:
            continue
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
            continue
        for job_name, job in doc["jobs"].items():
            if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
                continue
            # A job permissions map replaces the workflow permissions in full.
            perms = job.get("permissions", doc.get("permissions"))
            oidc = perms == "write-all" or (
                isinstance(perms, dict) and perms.get("id-token") == "write"
            )
            for idx, step in enumerate(job.get("steps") or [], 1):
                location = f".github/workflows/{name} (job {job_name}, step {idx})"
                if not isinstance(step, dict):
                    continue
                # External publisher internals are opaque, but the caller's
                # job permissions still govern its access to an OIDC token.
                action = str(step.get("uses", "")).partition("@")[0].lower()
                if "cargo-publish" in action:
                    yield PublishStep(name, location, oidc, False, frozenset(), None)
                if not isinstance(step.get("run"), str):
                    continue
                directory = "."
                env: dict[str, str] = {}
                for scope in (doc, job, step):
                    defaults = scope.get("defaults", {})
                    if isinstance(defaults, dict) and isinstance(defaults.get("run"), dict):
                        directory = defaults["run"].get("working-directory", directory)
                    if isinstance(scope.get("env"), dict):
                        env.update({k: str(v) for k, v in scope["env"].items()})
                cwd = _inside(repo, repo, str(step.get("working-directory", directory)))
                if cwd is None:
                    continue
                for dry_run, packages, risk in _scan(
                    repo, cwd, step["run"], location, location, env, set(), set(), count()
                ):
                    yield PublishStep(name, location, oidc, dry_run, packages, risk)
