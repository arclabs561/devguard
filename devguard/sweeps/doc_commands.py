"""Advisory checks of literal commands against local manifest targets.

Callers supply Markdown paths and the package working directory explicitly. No
Git discovery, shell commands, package managers, or network calls run here.
Only standalone npm run and cargo --example commands in shell fences are
supported. Findings establish missing targets, never that an example works.
"""

from __future__ import annotations

import json
import re
import shlex
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]*\Z")
_SHELLS = {"sh", "bash", "shell", "zsh"}
_MAX_BYTES = 256 * 1024


def _local(root: Path, relative: str | Path) -> Path:
    """Reject traversal and symlinks, including intermediate directories."""
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("path outside owner scope")
    candidate = root
    for part in rel.parts:
        candidate /= part
        if candidate.is_symlink():
            raise ValueError("symlink path")
    if not candidate.resolve().is_relative_to(root):
        raise ValueError("path outside owner scope")
    return candidate


def _read(path: Path) -> str:
    if not path.is_file():
        raise ValueError("missing or non-regular file")
    with path.open("rb") as handle:
        data = handle.read(_MAX_BYTES + 1)
    if len(data) > _MAX_BYTES:
        raise ValueError("file exceeds size limit")
    return data.decode("utf-8")


def _blocks(text: str) -> Iterable[tuple[int, list[tuple[int, str]], bool]]:
    fence = ""
    shell = False
    start = 0
    lines: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        match = _FENCE.match(line)
        if not fence:
            if match:
                fence, info = match.groups()
                shell = info.strip() in _SHELLS
                start = number
                lines = []
        elif (
            match
            and match[1][0] == fence[0]
            and len(match[1]) >= len(fence)
            and not match[2].strip()
        ):
            if shell:
                yield start, lines, True
            fence = ""
        elif shell:
            lines.append((number, line))
    if fence and shell:
        yield start, lines, False


def _command(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if line.startswith("$ "):
        line = line[2:]
    # Reject substitution, continuation, globbing and compound shell commands.
    if any(char in line for char in "$`\\;&|<>*?{}()"):
        return None
    try:
        args = shlex.split(line, comments=True)
    except ValueError:
        return None
    if args[:2] == ["npm", "run"] and len(args) >= 3:
        if not _NAME.fullmatch(args[2]):
            return None
        # Options such as --if-present and workspace selectors change semantics.
        if len(args) > 3 and args[3] != "--":
            return None
        return "npm", args[2]
    if len(args) >= 4 and args[0] == "cargo" and args[1] in {"run", "build", "test", "check"}:
        options = args[2 : args.index("--") if "--" in args else len(args)]
        target = None
        while options:
            option = options.pop(0)
            if option == "--example" and options and target is None:
                target = options.pop(0)
            elif option not in {"--release", "--offline", "--locked", "--frozen"}:
                return None
        if target is not None and _NAME.fullmatch(target):
            return "cargo", target
    return None


def _targets(root: Path, package: Path, engine: str) -> tuple[str, set[str]]:
    manifest = package / ("package.json" if engine == "npm" else "Cargo.toml")
    rel = manifest.relative_to(root)
    text = _read(_local(root, rel))
    if engine == "npm":
        data = json.loads(text)
        if not isinstance(data, dict) or not isinstance(data.get("scripts", {}), dict):
            raise ValueError("invalid scripts table")
        scripts = data.get("scripts", {})
        if any(not isinstance(value, str) for value in scripts.values()):
            raise ValueError("invalid script value")
        # npm run env has a built-in fallback even without a scripts entry.
        return str(rel), set(scripts) | {"env"}
    data = tomllib.loads(text)
    pkg = data.get("package")
    if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str):
        raise ValueError("virtual or invalid Cargo package")
    # Workspace default-members can select other packages from this directory.
    if "workspace" in data:
        raise ValueError("Cargo workspace selection unsupported")
    examples = data.get("example", [])
    if not isinstance(examples, list) or any(
        not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in examples
    ):
        raise ValueError("invalid Cargo example targets")
    names = {item["name"] for item in examples}
    # Edition 2015 has different auto-discovery defaults when explicit targets exist.
    if pkg.get("edition", "2015") == "2015":
        raise ValueError("Cargo edition 2015 discovery unsupported")
    if pkg.get("autoexamples", True) is not False:
        directory = _local(root, (package / "examples").relative_to(root))
        if directory.exists():
            for index, child in enumerate(directory.iterdir()):
                if index >= 1000:
                    raise ValueError("example directory exceeds limit")
                child = _local(root, child.relative_to(root))
                if child.is_file() and child.suffix == ".rs":
                    names.add(child.stem)
                elif child.is_dir():
                    main = _local(root, (child / "main.rs").relative_to(root))
                    if main.is_file():
                        names.add(child.name)
    return str(rel), names


def check_doc_commands(
    repo: Path, documents: Iterable[str | Path], *, package_root: str | Path = "."
) -> dict[str, Any]:
    """Check explicit Markdown inputs, assuming commands start at package_root.

    Unsupported blocks, unavailable manifests and unsafe paths produce skipped
    entries, not clean bills of health. Paths must be relative to the owner root.
    Callers must supply their own bounded, authorized (typically tracked) inputs.
    This is a filesystem hygiene check, not a hostile concurrent-FS sandbox.
    """
    root = repo.resolve(strict=True)
    if repo.is_symlink() or not root.is_dir():
        raise ValueError("owner must be a real directory")
    package = _local(root, package_root)
    if not package.is_dir():
        raise ValueError("package root must be a directory")
    findings: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    checked = 0
    cache: dict[str, tuple[str, set[str]] | None] = {}
    for index, relative in enumerate(documents):
        if index >= 1000:
            skipped.append({"reason": "document count exceeds limit"})
            break
        # Do not echo rejected absolute/out-of-scope input paths.
        try:
            path = _local(root, relative)
            if path.suffix.lower() != ".md":
                raise ValueError("not Markdown")
            text = _read(path)
        except (OSError, ValueError):
            skipped.append({"input_index": index, "reason": "unavailable or unsafe document"})
            continue
        rel = str(path.relative_to(root))
        for start, lines, closed in _blocks(text):
            commands = []
            for number, line in lines:
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                commands.append((number, _command(line)))
            if not closed or any(command is None for _, command in commands):
                skipped.append({"file": rel, "line": start, "reason": "unsupported shell block"})
                continue
            for number, command in commands:
                assert command is not None
                engine, target = command
                if engine not in cache:
                    try:
                        cache[engine] = _targets(root, package, engine)
                    except (OSError, ValueError):
                        cache[engine] = None
                resolved = cache[engine]
                if resolved is None:
                    skipped.append(
                        {
                            "file": rel,
                            "line": number,
                            "reason": "unavailable or unsupported manifest targets",
                        }
                    )
                    continue
                manifest, targets = resolved
                checked += 1
                if target not in targets:
                    findings.append(
                        {
                            "check": "doc_command_target",
                            "severity": "low",
                            "file": rel,
                            "line": number,
                            "engine": engine,
                            "target": target,
                            "manifest": manifest,
                            "message": "Documented command target is absent from the selected local package",
                        }
                    )
    return {
        "scope": {
            "package_root": str(package.relative_to(root)),
            "working_directory_assumed": True,
        },
        "findings": findings,
        "skipped": skipped,
        "commands_checked": checked,
    }
