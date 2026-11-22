"""Source patterns that turn missing work into successful checks."""

from __future__ import annotations

import ast
import re
import shlex
from pathlib import Path

from devguard.sweeps._common import contained_file

DESCRIPTIONS = {
    "copied_test_subject": "A test calls a local copy of a named production function without exercising the original",
    "flattened_python": "Python source is swallowed by a single shebang comment",
    "masked_test_command": "A test command discards its failure status",
    "fabricated_scan_report": "A failed scanner is replaced with an empty JSON report",
    "masked_search_error": "A count treats search errors (including missing inputs) as zero",
    "aliased_tier_costs": "Every comparison tier is populated from the same cost variable",
    "identical_method_branches": "Both paths through an algorithm selector perform the same work",
}

_PYTHON = re.compile(r"^#![^\n]*?\bpython(?:[23](?:\.\d+)?)?\b")
_PY_CODE = re.compile(r"\bdef [A-Za-z_]\w*\(|\bif __name__\s*==|\bfrom [\w.]+ import ")
_DISCARD = re.compile(r"\s+\|\|\s*(?:true|:)\s*(?:#.*)?$")
_COUNT = re.compile(r"""\brg\s+(?:-c|--count)\s+.*?\|\|\s*echo\s+["']?0["']?\s*\)""")
_HEREDOC = re.compile(r"""<<(-?)[ \t]*(['"]?)([\w.-]+)\2""")


# Only flag an explicitly constructed tier comparison. Shared model IDs and
# equal observed prices are legitimate.
_ALIASED_COST = re.compile(
    r"(?m)^\s*(?:const|let)\s+\w+(?:\s*:\s*[\w<>]+)?\s*=\s*"
    r"\{\s*fast:\s*(\w*[Cc]ost\w*)\s*,\s*balanced:\s*\1\s*,\s*best:\s*\1\s*,?\s*\}"
)


_SCAN_COMMAND = re.compile(r"^(?:cargo geiger|opengrep scan|ast-grep scan|semgrep scan)\b")
_EMPTY_REPORT = re.compile(r"""^echo\s+(['"])(?:\{\}|\[\]|\{"results":\[\]\})\1\s*>[^>]""")


def _shell_checks(source: str) -> set[str]:
    findings: set[str] = set()
    end = ""
    strip_tabs = False
    scanner_fallback = False
    for line in source.splitlines():
        if end:
            if (line.lstrip("\t") if strip_tabs else line) == end:
                end = ""
            continue
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        doc = _HEREDOC.search(line)
        if doc:
            end = doc[3]
            strip_tabs = bool(doc[1])
        if scanner_fallback and _EMPTY_REPORT.match(line):
            findings.add("fabricated_scan_report")
        scanner_fallback = False
        if _SCAN_COMMAND.match(line) and "||" in line:
            fallback = line.rsplit("||", 1)[1].strip()
            if _EMPTY_REPORT.match(fallback):
                findings.add("fabricated_scan_report")
            scanner_fallback = fallback == "{"
        if _COUNT.search(line) and not line.startswith(("echo ", "printf ")):
            findings.add("masked_search_error")
        mask = _DISCARD.search(line)
        if not mask:
            continue
        try:
            cmd = shlex.split(line[: mask.start()], comments=True)
        except ValueError:
            continue
        if not cmd:
            continue
        name = Path(cmd[0]).name
        is_test = name in {"pytest", "py.test"} or cmd[:2] in (
            ["cargo", "test"],
            ["npm", "test"],
            ["node", "--test"],
            ["go", "test"],
        )
        if name in {"python", "python3"}:
            is_test = cmd[1:3] in (["-m", "pytest"], ["-m", "unittest"]) or (
                len(cmd) > 1 and Path(cmd[1]).name.startswith("test_") and cmd[1].endswith(".py")
            )
        if is_test:
            findings.add("masked_test_command")
    return findings


_MIRRORED = re.compile(r"\bmirrors the logic (?:from|of)\s+`?((?:\w+\.)+\w+)", re.I)


def _copied_subject(source: str) -> bool:
    if not _MIRRORED.search(source):
        return False
    try:
        root = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return False
    funcs = [
        node for node in ast.walk(root) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    # Any call or import of the named subject could be a legitimate differential test.
    targets = {node.attr for node in ast.walk(root) if isinstance(node, ast.Attribute)}
    targets.update(node.id for node in ast.walk(root) if isinstance(node, ast.Name))
    targets.update(node.name for node in ast.walk(root) if isinstance(node, ast.alias))
    test_calls = {
        call.func.id
        for func in funcs
        if func.name.startswith("test_")
        for call in ast.walk(func)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
    }
    for func in funcs:
        match = _MIRRORED.search(ast.get_docstring(func) or "")
        if match and func.name in test_calls and match[1].rsplit(".", 1)[-1] not in targets:
            return True
    return False


def _python_checks(source: str) -> set[str]:
    body = source.rstrip("\r\n")
    if "\n" not in body and _PYTHON.match(body) and _PY_CODE.search(body):
        return {"flattened_python"}
    if "else:" not in source or not any(word in source for word in ("method", "algorithm", "mode")):
        return set()
    try:
        root = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return set()
    for node in ast.walk(root):
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        selector = node.test.left
        if not isinstance(selector, ast.Name) or selector.id not in {"method", "algorithm", "mode"}:
            continue
        if node.orelse and [ast.dump(x) for x in node.body] == [ast.dump(x) for x in node.orelse]:
            return {"identical_method_branches"}
    return set()


def find_false_passes(repo: Path, tracked: list[str]) -> dict[str, list[str]]:
    findings: dict[str, list[str]] = {}
    for rel in tracked:
        path = repo / rel
        if path.suffix not in {".py", ".sh", ".bash", ".ts", ".mjs", ".js"} or not contained_file(
            path, repo
        ):
            continue
        if path.stat().st_size > 1024 * 1024:
            continue
        source = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix == ".py":
            checks = _python_checks(source)
            if (path.name.startswith("test_") or path.stem.endswith("_test")) and _copied_subject(
                source
            ):
                checks.add("copied_test_subject")
        elif path.suffix in {".sh", ".bash"}:
            checks = _shell_checks(source)
        else:
            checks = {"aliased_tier_costs"} if _ALIASED_COST.search(source) else set()
        for check in sorted(checks):
            findings.setdefault(check, []).append(rel)
    return findings
