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


def _multi_package(repo: Path, cwd: Path, args: list[str]) -> bool:
    packages = set(_options(args, "-p", "--package"))
    if len(packages) > 1:
        return True
    manifest = _inside(repo, cwd, (_options(args, "--manifest-path") or ["Cargo.toml"])[-1])
    if not manifest or not manifest.is_file():
        return False
    try:
        config = tomllib.loads(manifest.read_text())
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return False
    workspace = config.get("workspace")
    if not isinstance(workspace, dict):
        return False
    root = config.get("package", {}).get("name")
    members = workspace.get("members", [])
    if not packages and "--workspace" not in args and "--all" not in args:
        members = workspace.get("default-members", ["."] if root else members)
    elif root:
        members = [".", *members]
    names = set()
    excluded = _options(args, "--exclude")
    for pattern in members:
        if (
            not isinstance(pattern, str)
            or Path(pattern).is_absolute()
            or ".." in Path(pattern).parts
        ):
            continue
        for member in manifest.parent.glob(f"{pattern}/Cargo.toml"):
            if not member.resolve().is_relative_to(repo):
                continue
            relative = member.parent.relative_to(manifest.parent).as_posix()
            if any(fnmatch.fnmatchcase(relative, g) for g in workspace.get("exclude", [])):
                continue
            try:
                name = tomllib.loads(member.read_text()).get("package", {}).get("name")
            except (OSError, UnicodeError, tomllib.TOMLDecodeError):
                continue
            if not name or any(fnmatch.fnmatchcase(name, g) for g in excluded):
                continue
            if not packages or any(fnmatch.fnmatchcase(name, g) for g in packages):
                names.add(name)
                if len(names) > 1:
                    return True
    return False


@dataclass(frozen=True)
class StagingRisk:
    source: str
    line: int
    workflow_step: str


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
) -> Iterator[StagingRisk]:
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
        if args[:1] != ["publish"] or "--dry-run" not in args or "--no-verify" in args:
            continue
        if not _multi_package(repo, cwd, args):
            continue
        inherited = (
            values.get("CARGO_TARGET_DIR", "") if "CARGO_TARGET_DIR" in exported | assigned else ""
        )
        target = (_options(args, "--target-dir") or [inherited])[-1]
        target = _VAR.sub(lambda m: values.get(m[1] or m[2], m[0]), target)
        # A repeated check with the same allocated directory can also be stale.
        if not target.startswith("\0mktemp:") or ".." in target.split("/") or target in used:
            yield StagingRisk(source, line, step)
        used.add(target)


def staging_risks(repo: Path, workflows: list[tuple[str, str]]) -> Iterator[StagingRisk]:
    repo = repo.resolve()
    for name, text in workflows:
        if "run:" not in text:
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
            for idx, step in enumerate(job.get("steps") or [], 1):
                if not isinstance(step, dict) or not isinstance(step.get("run"), str):
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
                location = f".github/workflows/{name} (job {job_name}, step {idx})"
                yield from _scan(
                    repo, cwd, step["run"], location, location, env, set(), set(), count()
                )
