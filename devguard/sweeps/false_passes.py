"""Source patterns that turn missing work into successful checks."""

from __future__ import annotations

import ast
import io
import re
import shlex
import tokenize
from pathlib import Path

import yaml  # type: ignore[import-untyped]

from devguard.sweeps._common import contained_file

DESCRIPTIONS = {
    "tautological_test_assertion": "An unconditional True operand makes a test assertion pass",
    "conflicting_subprocess_output": "A subprocess.run call combines capture_output=True with an explicit output stream",
    "swallowed_test_assertion": "A test discards an assertion failure or converts it to a skip in a broad exception handler",
    "copied_test_subject": "A test calls a local copy of a named production function without exercising the original",
    "flattened_shell": "A command follows set -euo pipefail without a shell separator",
    "flattened_python": "A shebang or a long comment contains a flattened Python implementation",
    "missing_just_script": "A root justfile recipe runs a literal local script missing from the git index",
    "masked_test_command": "A test command discards its failure status",
    "placeholder_rust_trait": "A public trait describes future behavior and contains only an implementation TODO",
    "fabricated_scan_report": "A failed scanner is replaced with an empty JSON report",
    "masked_search_error": "A count treats search errors (including missing inputs) as zero",
    "identical_method_branches": "Both paths through a selector perform the same work",
}

_PYTHON = re.compile(r"^#![^\n]*?\bpython(?:[23](?:\.\d+)?)?\b")
_PY_CODE = re.compile(r"\bdef [A-Za-z_]\w*\(|\bif __name__\s*==|\bfrom [\w.]+ import ")
_COUNT = re.compile(r"""\brg\s+(?:-c|--count)\s+.*?\|\|\s*echo\s+["']?0["']?\s*\)""")
_HEREDOC = re.compile(r"""<<(-?)[ \t]*(['"]?)([\w.-]+)\2""")


# Require both explicit placeholder docs and an unimplemented body. An empty
# trait by itself is a valid Rust marker.
_PLACEHOLDER_TRAIT = re.compile(
    r"(?m)^(?P<docs>(?:[ \t]*///[^\n]*\n)+)"
    r"[ \t]*pub[ \t]+trait[ \t]+[A-Za-z_]\w*[ \t]*\{"
    r"(?P<body>(?:\s|//[^\n]*\n)*)\}"
)


def _placeholder_trait(source: str) -> bool:
    if "placeholder" not in source.lower() or "TODO" not in source:
        return False
    return any(
        "placeholder" in m["docs"].lower() and "TODO" in m["body"]
        for m in _PLACEHOLDER_TRAIT.finditer(source)
    )


_SCAN_COMMAND = re.compile(r"^(?:cargo geiger|opengrep scan|ast-grep scan|semgrep scan)\b")
_EMPTY_REPORT = re.compile(r"""^echo\s+(['"])(?:\{\}|\[\]|\{"results":\[\]\})\1\s*>[^>]""")


def _masked_test(line: str) -> bool:
    if "||" not in line:
        return False
    # Keep quotes on tokens so an argument containing shell operators is inert.
    lexer = shlex.shlex(line, posix=False, punctuation_chars=";&|")
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return False
    if len(tokens) < 3 or tokens[-2] != "||" or tokens[-1] not in {"true", ":"}:
        return False
    chain = tokens[:-2]
    for i in range(len(chain) - 1, -1, -1):
        if chain[i] in {"||", ";"}:
            chain = chain[i + 1 :]
            break
    start = 0
    for i, token in enumerate([*chain, "&&"]):
        if token == "&&":
            if _test_command(chain[start:i]):
                return True
            start = i + 1
    return False


def _test_command(cmd: list[str]) -> bool:
    if "|" in cmd:
        return False  # The exit status depends on the shell's pipeline settings.
    if cmd[:2] == ["uv", "run"]:
        cmd = cmd[2:]
    if not cmd:
        return False
    name = Path(cmd[0]).name
    if name in {"python", "python3"}:
        return cmd[1:3] in (["-m", "pytest"], ["-m", "unittest"]) or (
            len(cmd) > 1 and Path(cmd[1]).name.startswith("test_") and cmd[1].endswith(".py")
        )
    return name in {"pytest", "py.test"} or cmd[:2] in (
        ["cargo", "test"],
        ["npm", "test"],
        ["node", "--test"],
        ["go", "test"],
    )


def _pre_commit_checks(source: str) -> set[str]:
    if "||" not in source:
        return set()
    try:
        config = yaml.safe_load(source)
    except (yaml.YAMLError, RecursionError):
        return set()
    repos = config.get("repos") if isinstance(config, dict) else None
    for repo in repos if isinstance(repos, list) else []:
        if not isinstance(repo, dict) or repo.get("repo") != "local":
            continue
        hooks = repo.get("hooks")
        for hook in hooks if isinstance(hooks, list) else []:
            entry = hook.get("entry") if isinstance(hook, dict) else None
            if not isinstance(entry, str):
                continue
            try:
                args = shlex.split(entry)
            except ValueError:
                continue
            if len(args) >= 3 and Path(args[0]).name in {"sh", "bash"} and args[1] == "-c":
                if "masked_test_command" in _shell_checks(args[2]):
                    return {"masked_test_command"}
    return set()


def _workflow_checks(source: str) -> set[str]:
    try:
        workflow = yaml.safe_load(source)
    except (yaml.YAMLError, RecursionError):
        return set()
    def default_shell(owner: dict, fallback: str) -> str:
        defaults = owner.get("defaults")
        run = defaults.get("run") if isinstance(defaults, dict) else None
        return run.get("shell", fallback) if isinstance(run, dict) else fallback

    jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
    findings: set[str] = set()
    for job in jobs.values() if isinstance(jobs, dict) else ():
        if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
            continue
        inherited = default_shell(job, default_shell(workflow, ""))
        for step in job["steps"]:
            if not isinstance(step, dict) or not isinstance(step.get("run"), str):
                continue
            shell = step.get("shell", inherited)
            if not isinstance(shell, str):
                continue
            tokens = shell.split()
            if not tokens or Path(tokens[0]).name in ("bash", "sh"):
                findings.update(_shell_checks(step["run"]))
    return findings


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
        if re.match(r"^set\s+-[eu]+o\s+pipefail\s+(?:echo|printf|python3?|cargo)\s", line):
            findings.add("flattened_shell")
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
        if _masked_test(line):
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


_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _scope_nodes(nodes, stop_at=()):
    for node in nodes:
        if isinstance(node, _SCOPES + stop_at):
            continue
        yield node
        yield from _scope_nodes(ast.iter_child_nodes(node), stop_at)


def _catches_assertion(kind: ast.expr | None) -> bool:
    if kind is None:
        return True
    if isinstance(kind, ast.Tuple):
        return any(_catches_assertion(item) for item in kind.elts)
    if (
        isinstance(kind, ast.Attribute)
        and isinstance(kind.value, ast.Name)
        and kind.value.id == "builtins"
    ):
        return kind.attr in {"AssertionError", "Exception", "BaseException"}
    return isinstance(kind, ast.Name) and kind.id in {
        "AssertionError",
        "Exception",
        "BaseException",
    }


def _assertion_checks(source: str) -> set[str]:
    findings: set[str] = set()
    if "assert" not in source or ("except" not in source and "True" not in source):
        return findings
    try:
        root = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return findings
    candidates = list(root.body)
    for cls in root.body:
        if isinstance(cls, ast.ClassDef) and cls.name.startswith("Test"):
            candidates.extend(cls.body)
    for func in candidates:
        if not isinstance(
            func, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) or not func.name.startswith("test_"):
            continue
        for node in _scope_nodes(func.body):
            if (
                isinstance(node, ast.Assert)
                and isinstance(node.test, ast.BoolOp)
                and isinstance(node.test.op, ast.Or)
            ):
                if any(isinstance(v, ast.Constant) and v.value is True for v in node.test.values):
                    findings.add("tautological_test_assertion")
            if not isinstance(node, ast.Try):
                continue
            handler = next((h for h in node.handlers if _catches_assertion(h.type)), None)
            if not handler:
                continue
            # Keep a deliberate, narrowly caught prerequisite skip distinct from
            # a handler that turns every error, including test failures, into a skip.
            skip = len(handler.body) == 1 and ast.unparse(handler.body[0]).startswith(
                "pytest.skip("
            )
            broad = handler.type is None or any(
                isinstance(t, ast.Name) and t.id in {"Exception", "BaseException"}
                for t in ast.walk(handler.type)
            )
            if not (all(isinstance(stmt, ast.Pass) for stmt in handler.body) or (skip and broad)):
                continue
            # A nested try or context manager can consume its own exceptions.
            direct = _scope_nodes(node.body, (ast.Try, ast.TryStar, ast.With, ast.AsyncWith))
            if any(isinstance(stmt, ast.Assert) for stmt in direct):
                findings.add("swallowed_test_assertion")
    return findings


_BURIED_DEF = re.compile(r"\bdef [A-Za-z_]\w*\([^()]*\)(?:\s*->[^:]+)?:")
_BURIED_CLASS = re.compile(r"\bclass [A-Za-z_]\w*(?:\([^()]*\))?:")


def _buried_implementation(source: str) -> bool:
    # Tokenize only plausible candidates. Examples inside strings and docstrings
    # may look exactly like damaged source, but do not hide executable code.
    if not any(
        len(line) > 350 and line.count("def ") >= 2 and "#" in line for line in source.splitlines()
    ):
        return False
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type != tokenize.COMMENT or len(token.string) <= 350:
                continue
            if _BURIED_CLASS.search(token.string) and len(_BURIED_DEF.findall(token.string)) >= 2:
                return True
    except (tokenize.TokenError, IndentationError):
        pass
    return False


def _conflicting_subprocess_output(source: str) -> bool:
    if "capture_output" not in source or "subprocess" not in source:
        return False
    try:
        root = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return False
    # Limit the rule to an explicitly imported stdlib module and known streams.
    modules = {
        alias.asname or "subprocess"
        for stmt in root.body
        if isinstance(stmt, ast.Import)
        for alias in stmt.names
        if alias.name == "subprocess"
    }
    for call in ast.walk(root):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
            continue
        module = call.func.value
        if not isinstance(module, ast.Name) or module.id not in modules or call.func.attr != "run":
            continue
        args = {kw.arg: kw.value for kw in call.keywords}
        capture = args.get("capture_output")
        if not (isinstance(capture, ast.Constant) and capture.value is True):
            continue
        for field in ("stdout", "stderr"):
            stream = args.get(field)
            if (
                isinstance(stream, ast.Attribute)
                and isinstance(stream.value, ast.Name)
                and stream.value.id in modules
                and stream.attr in {"PIPE", "STDOUT", "DEVNULL"}
            ):
                return True
    return False


def _python_checks(source: str) -> set[str]:
    body = source.rstrip("\r\n")
    if "\n" not in body and _PYTHON.match(body) and _PY_CODE.search(body):
        return {"flattened_python"}
    if _buried_implementation(source):
        return {"flattened_python"}
    if "else:" not in source:
        return set()
    try:
        root = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return set()
    for node in ast.walk(root):
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        # A literal selector has no call in its condition. Its name carries no
        # information about whether the two arms actually do different work.
        test = node.test
        if not (
            isinstance(test.left, ast.Name)
            and len(test.ops) == 1
            and isinstance(test.ops[0], (ast.Eq, ast.NotEq, ast.Is, ast.IsNot))
            and isinstance(test.comparators[0], ast.Constant)
        ):
            continue
        if all(
            isinstance(stmt, ast.Pass)
            or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant))
            for stmt in node.body
        ):
            continue
        if node.orelse and [ast.dump(x) for x in node.body] == [ast.dump(x) for x in node.orelse]:
            return {"identical_method_branches"}
    return set()


_JUST_SCRIPT = re.compile(
    r"^[ \t]+@?(?:(?:uv +run +)?(?:python3?|bash|sh) +(?:\./)?|\./)"
    r"((?:scripts|tests)/[A-Za-z0-9_./-]+\.(?:py|sh))(?=\s|$)"
)


def _missing_just_scripts(source: str, tracked: set[str]) -> list[str]:
    missing: set[str] = set()
    # A working-directory override, generated recipe or multiline shell command
    # can change how a relative path resolves. Inspect only simple recipe lines.
    if "working-directory" in source:
        return []
    previous = ""
    script_recipe = False
    for line in source.splitlines():
        if line and not line[0].isspace():
            script_recipe = False
        elif line.lstrip().startswith("#!"):
            script_recipe = True
        if not script_recipe and not previous.endswith("\\"):
            match = _JUST_SCRIPT.match(line)
            if match and ".." not in Path(match[1]).parts and match[1] not in tracked:
                missing.add(match[1])
        previous = line.rstrip()
    return sorted(missing)


def find_false_passes(repo: Path, tracked: list[str]) -> dict[str, list[str]]:
    findings: dict[str, list[str]] = {}
    for name in ("justfile", "Justfile"):
        path = repo / name
        if name in tracked and contained_file(path, repo) and path.stat().st_size <= 1024 * 1024:
            missing = _missing_just_scripts(
                path.read_text(encoding="utf-8", errors="replace"), set(tracked)
            )
            if missing:
                findings.setdefault("missing_just_script", []).extend(
                    f"{name} -> {script}" for script in missing
                )
    for rel in tracked:
        path = repo / rel
        workflow = path.parent == repo / ".github/workflows" and path.suffix in {".yaml", ".yml"}
        if (
            not workflow
            and path.name != ".pre-commit-config.yaml"
            and path.suffix
            not in {
                ".py",
                ".sh",
                ".bash",
                ".rs",
            }
        ) or not contained_file(path, repo):
            continue
        if path.stat().st_size > 1024 * 1024:
            continue
        source = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix == ".py":
            checks = _python_checks(source)
            if _conflicting_subprocess_output(source):
                checks.add("conflicting_subprocess_output")
            if path.name.startswith("test_") or path.stem.endswith("_test"):
                if _copied_subject(source):
                    checks.add("copied_test_subject")
                checks.update(_assertion_checks(source))
        elif workflow:
            checks = _workflow_checks(source)
        elif path.name == ".pre-commit-config.yaml":
            checks = _pre_commit_checks(source)
        elif path.suffix == ".rs":
            checks = {"placeholder_rust_trait"} if _placeholder_trait(source) else set()
        else:  # shell sources
            checks = _shell_checks(source)
        for check in sorted(checks):
            findings.setdefault(check, []).append(rel)
    return findings
