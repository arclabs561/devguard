"""Audit repo-supplied configs that execute code when a repo is opened.

Cloning a repo and opening it in Claude Code, VS Code, a devcontainer or a
direnv shell can run commands the repo chose. This sweep inventories those
commands in *tracked* files only: every command is reported at medium so the
owner knows what runs on open, and known-bad shapes (pipe-to-shell downloads,
reverse shells, decode-and-execute) are high.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from devguard.sweeps._common import iter_git_repos
from devguard.sweeps._common import utc_now as _utc_now

_DANGEROUS_RES = [
    (
        re.compile(r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"),
        "pipes a download to a shell",
    ),
    (re.compile(r"/dev/(?:tcp|udp)/"), "opens a raw network socket (reverse shell)"),
    (re.compile(r"\bnc\b.*\s-[ec]\b"), "runs netcat with -e"),
    (re.compile(r"\bbase64\s+(?:-d|--decode)\b.*\|"), "decodes and executes data"),
    (re.compile(r"\bbash\s+-i\b"), "starts an interactive shell"),
    (re.compile(r"\beval\b"), "uses eval"),
    (re.compile(r"\bpython3?\s+-c\b"), "runs inline Python"),
]

_DEVCONTAINER_HOOKS = (
    "initializeCommand",
    "onCreateCommand",
    "updateContentCommand",
    "postCreateCommand",
    "postStartCommand",
    "postAttachCommand",
)
_COMMAND_KEYS = frozenset({"command", "commands", "run", "script"})


def _strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas outside strings."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _load_json(path: Path) -> Any:
    try:
        return json.loads(_strip_jsonc(path.read_text(encoding="utf-8", errors="replace")))
    except (OSError, json.JSONDecodeError):
        return None


def _command_strings(value: Any) -> Iterator[str]:
    """Yield a command given as a string, an argv list, or an object of either."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list) and all(isinstance(v, str) for v in value):
        yield " ".join(value)
    elif isinstance(value, dict):
        for v in value.values():
            yield from _command_strings(v)


def _nested_commands(data: Any) -> Iterator[str]:
    """Yield every string under a command-like key anywhere in a JSON document."""
    if isinstance(data, dict):
        for k, v in data.items():
            if k in _COMMAND_KEYS:
                yield from _command_strings(v)
            else:
                yield from _nested_commands(v)
    elif isinstance(data, list):
        for v in data:
            yield from _nested_commands(v)


def _danger(command: str) -> str | None:
    for rx, why in _DANGEROUS_RES:
        if rx.search(command):
            return why
    return None


def _shorten(command: str, limit: int = 120) -> str:
    one_line = " ".join(command.split())
    return one_line if len(one_line) <= limit else one_line[: limit - 3] + "..."


class _Collector:
    def __init__(self, repo: Path) -> None:
        self.repo = repo
        self.findings: list[dict[str, Any]] = []

    def add(self, file: str, check_id: str, severity: str, message: str) -> None:
        self.findings.append(
            {
                "repo_path": str(self.repo),
                "file": file,
                "check_id": check_id,
                "severity": severity,
                "message": message,
            }
        )

    def command(self, file: str, where: str, command: str) -> None:
        why = _danger(command)
        if why:
            self.add(file, "dangerous_open_command", "high", f"{where} {why}: {_shorten(command)}")
        else:
            self.add(file, "runs_on_open", "medium", f"{where} runs: {_shorten(command)}")


def _audit_claude_settings(c: _Collector, rel: str, data: dict[str, Any]) -> None:
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event, matchers in hooks.items():
            for cmd in _nested_commands(matchers):
                c.command(rel, f"{event} hook", cmd)
    helper = data.get("apiKeyHelper")
    if isinstance(helper, str) and helper.strip():
        c.command(rel, "apiKeyHelper", helper)
    env = data.get("env")
    if isinstance(env, dict):
        for key, value in env.items():
            if re.search(r"(?:_BASE_URL|_PROXY)$", str(key)) and isinstance(value, str):
                c.add(
                    rel,
                    "api_endpoint_override",
                    "high",
                    f"env.{key} redirects API traffic to {_shorten(value, 80)}",
                )
    if data.get("enableAllProjectMcpServers") is True:
        c.add(
            rel,
            "auto_enable_mcp_servers",
            "medium",
            "enableAllProjectMcpServers starts every repo MCP server without asking",
        )
    allow = (data.get("permissions") or {}).get("allow")
    if isinstance(allow, list) and any(a in ("Bash", "Bash(*)") for a in allow):
        c.add(
            rel,
            "unrestricted_bash",
            "high",
            "permissions.allow grants unrestricted Bash to anyone who opens the repo",
        )


def _audit_vscode_tasks(c: _Collector, rel: str, data: dict[str, Any]) -> None:
    for task in data.get("tasks") or []:
        if not isinstance(task, dict):
            continue
        if (task.get("runOptions") or {}).get("runOn") != "folderOpen":
            continue
        cmd = " ".join(
            s for s in [task.get("command"), *(task.get("args") or [])] if isinstance(s, str)
        )
        c.command(rel, f"task '{task.get('label', '?')}' (folderOpen)", cmd)


def _audit_vscode_settings(c: _Collector, rel: str, data: dict[str, Any]) -> None:
    for key in data:
        if str(key).startswith("terminal.integrated.env."):
            c.add(
                rel,
                "terminal_env_override",
                "medium",
                f"{key} sets environment variables for every terminal in the repo",
            )


def _audit_devcontainer(c: _Collector, rel: str, data: dict[str, Any]) -> None:
    for hook in _DEVCONTAINER_HOOKS:
        for cmd in _command_strings(data.get(hook)):
            c.command(rel, hook, cmd)


_JSON_AUDITS = {
    ".claude/settings.json": _audit_claude_settings,
    ".vscode/tasks.json": _audit_vscode_tasks,
    ".vscode/settings.json": _audit_vscode_settings,
    ".devcontainer/devcontainer.json": _audit_devcontainer,
    ".devcontainer.json": _audit_devcontainer,
}
# Hook files whose every command runs on an editor or deploy event.
_HOOK_FILES = (".cursor/hooks.json", ".piku/hooks.json")


def _tracked(repo: Path) -> set[str]:
    res = subprocess.run(
        ["git", "ls-files", "-z"], cwd=repo, capture_output=True, text=True, timeout=30
    )
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip()[:200] or f"git ls-files exit={res.returncode}")
    return {p for p in res.stdout.split("\0") if p}


def _inside(path: Path, repo: Path) -> bool:
    try:
        path.resolve().relative_to(repo.resolve())
    except ValueError:
        return False
    return True


def audit_repo(repo: Path) -> list[dict[str, Any]]:
    c = _Collector(repo)
    tracked = _tracked(repo)
    for rel in sorted(set(_JSON_AUDITS) | set(_HOOK_FILES) | {".envrc"}):
        if rel not in tracked:
            continue
        path = repo / rel
        if not _inside(path, repo):
            c.add(rel, "symlink_escapes_repo", "medium", f"{rel} links outside the repo; not read")
            continue
        if rel == ".envrc":
            text = path.read_text(encoding="utf-8", errors="replace")
            body = "\n".join(
                ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")
            )
            if body:
                c.command(rel, "direnv .envrc", body)
            continue
        data = _load_json(path)
        if not isinstance(data, dict):
            continue
        if rel in _HOOK_FILES:
            for cmd in _nested_commands(data):
                c.command(rel, "hook", cmd)
        else:
            _JSON_AUDITS[rel](c, rel, data)
    return c.findings


def audit_exec_configs(
    *,
    dev_root: Path,
    max_depth: int,
    exclude_repo_globs: list[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    findings: list[dict[str, Any]] = []
    repos = sorted(iter_git_repos(dev_root, max_depth=max_depth, exclude_globs=exclude_repo_globs))
    for repo in repos:
        try:
            findings.extend(audit_repo(repo))
        except (OSError, subprocess.SubprocessError, RuntimeError) as e:
            errors.append(f"{repo}: {e}")
    high = sum(1 for f in findings if f["severity"] == "high")
    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {"dev_root": str(dev_root), "max_depth": max_depth, "repos_scanned": len(repos)},
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "high_findings": high,
            "total_errors": high,
        },
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
