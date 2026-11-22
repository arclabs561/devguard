"""Source patterns that turn missing work into successful checks."""

from __future__ import annotations

import ast
import re
import shlex
from pathlib import Path

from devguard.sweeps._common import contained_file

DESCRIPTIONS = {
    "flattened_python": "Python source is swallowed by a single shebang comment",
    "masked_test_command": "A test command discards its failure status",
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


def _shell_checks(source: str) -> set[str]:
    findings: set[str] = set()
    end = ""
    strip_tabs = False
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
        if path.suffix not in {".py", ".sh", ".bash", ".ts", ".mjs", ".js"} or not contained_file(path, repo):
            continue
        if path.stat().st_size > 1024 * 1024:
            continue
        source = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix == ".py":
            checks = _python_checks(source)
        elif path.suffix in {".sh", ".bash"}:
            checks = _shell_checks(source)
        else:
            checks = {"aliased_tier_costs"} if _ALIASED_COST.search(source) else set()
        for check in sorted(checks):
            findings.setdefault(check, []).append(rel)
    return findings
