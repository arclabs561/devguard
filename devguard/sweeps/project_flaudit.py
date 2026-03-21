"""Project flaudit sweep: files-to-prompt per project + OpenRouter/Gemini analysis.

For each project (or k most recently edited), aggregates README, implementation,
and tests into a prompt, then uses OpenRouter + Gemini to find flaws:
- README vs implementation drift
- README vs tests mismatch
- Disobedience of project/workspace rules (e.g. .cursor/rules)
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# File patterns for files-to-prompt aggregation
README_GLOBS = ["README*", "readme*", "Readme*"]
IMPL_EXTENSIONS = {".py", ".rs", ".ts", ".tsx", ".js", ".jsx", ".go", ".java", ".kt"}
IMPL_EXCLUDE_DIRS = {
    ".git", "node_modules", "target", ".venv", "venv", "__pycache__",
    ".pytest_cache", ".ruff_cache", "dist", "build", ".next",
}
TEST_PATTERNS = [
    "**/test_*.py", "**/tests/**/*.py", "**/*_test.py", "**/*.test.ts",
    "**/*.spec.ts", "**/__tests__/**/*", "**/test/**/*",
]
RULES_GLOBS = [".cursor/rules/**/*.mdc", ".cursor/rules/**/*.md"]


@dataclass
class FlauditFinding:
    """A single flaw finding from the LLM analysis."""

    severity: str  # critical, high, medium, low
    category: str  # readme_impl_drift, readme_tests_mismatch, rules_violation, other
    description: str
    file_ref: str | None = None
    suggestion: str | None = None
    rule_ref: str | None = None  # For rules_violation: which rule file (e.g. user-core.mdc)


@dataclass
class ProjectFlauditResult:
    """Result of flaudit for one project."""

    repo_path: str
    prompt_char_count: int
    findings: list[FlauditFinding] = field(default_factory=list)
    error: str | None = None


def _discover_git_repos(
    dev_root: Path,
    max_depth: int = 2,
    depth_0_skip_prefixes: list[str] | None = None,
    depth_0_allow_names: list[str] | None = None,
) -> list[Path]:
    """Discover git repos under dev_root (bounded by max_depth).

    depth_0_skip_prefixes: at depth 0, skip dirs whose names start with these.
    depth_0_allow_names: dir names to allow despite skip_prefixes (e.g. _infra).
    """
    repos: list[Path] = []
    dev_root = dev_root.expanduser().resolve()
    if not dev_root.exists():
        return repos

    skip_prefixes = depth_0_skip_prefixes if depth_0_skip_prefixes is not None else ["_", "."]
    allow_names = set(depth_0_allow_names if depth_0_allow_names is not None else ["_infra"])

    if (dev_root / ".git").exists():
        repos.append(dev_root)

    frontier: list[tuple[Path, int]] = [(dev_root, 0)]
    while frontier:
        cur, depth = frontier.pop()
        if depth >= max_depth:
            continue
        try:
            children = list(cur.iterdir())
        except (OSError, PermissionError):
            continue
        for child in children:
            if not child.is_dir():
                continue
            name = child.name
            if name in {".git", ".venv", "venv", "node_modules", "target", ".cache", ".pytest_cache", ".ruff_cache"}:
                continue
            if depth == 0 and skip_prefixes:
                if any(name.startswith(p) for p in skip_prefixes) and name not in allow_names:
                    continue
            if (child / ".git").exists():
                repos.append(child)
                continue
            frontier.append((child, depth + 1))

    seen: set[Path] = set()
    out: list[Path] = []
    for r in repos:
        rr = r.resolve()
        if rr in seen:
            continue
        seen.add(rr)
        out.append(rr)
    return out


def _git_ls_files(repo: Path) -> list[str]:
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


def _git_files_changed_last_n(repo: Path, n: int) -> set[str]:
    """Return set of file paths changed in last n commits (relative to repo root)."""
    proc = subprocess.run(
        ["git", "-C", str(repo), "log", "-n", str(n), "--name-only", "--format="],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
    )
    if proc.returncode != 0:
        return set()
    out = proc.stdout.decode("utf-8", errors="replace")
    return {p.strip() for p in out.splitlines() if p.strip()}


def _repo_last_commit_time(repo: Path) -> float:
    """Return Unix timestamp of last commit (for sorting by recency)."""
    proc = subprocess.run(
        ["git", "-C", str(repo), "log", "-1", "--format=%ct"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
    )
    if proc.returncode != 0:
        return 0.0
    try:
        return float(proc.stdout.decode().strip() or "0")
    except ValueError:
        return 0.0


def _is_test_file(rel_path: str) -> bool:
    for pat in TEST_PATTERNS:
        if fnmatch.fnmatch(rel_path, pat):
            return True
    return False


def _is_impl_file(rel_path: str) -> bool:
    p = Path(rel_path)
    if p.suffix.lower() not in IMPL_EXTENSIONS:
        return False
    parts = p.parts
    if any(d in parts for d in IMPL_EXCLUDE_DIRS):
        return False
    if _is_test_file(rel_path):
        return False
    return True


def _is_readme(rel_path: str) -> bool:
    name = Path(rel_path).name
    for g in README_GLOBS:
        if fnmatch.fnmatch(name, g):
            return True
    return False


def _is_rules_file(rel_path: str) -> bool:
    for g in RULES_GLOBS:
        if fnmatch.fnmatch(rel_path, g):
            return True
    return False


def _read_file_safe(path: Path, max_chars: int = 50_000) -> str | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        if len(text) > max_chars:
            text = text[:max_chars] + "\n\n[... truncated ...]"
        return text
    except (OSError, UnicodeDecodeError):
        return None


# Manifest files to always include (entry points, features, deps)
MANIFEST_FILES = ["pyproject.toml", "Cargo.toml", "package.json"]
MANIFEST_MAX_CHARS = 4_000

# Default workspace rule files when workspace_rules_include is empty
DEFAULT_WORKSPACE_RULES = [
    "user-core.mdc",
    "user-output-structure.mdc",
    "hygiene.mdc",
    "docs.mdc",
]


def files_to_prompt(
    repo: Path,
    tracked: list[str],
    max_readme_chars: int = 15_000,
    max_impl_files: int = 20,
    max_impl_chars_per_file: int = 8_000,
    max_test_files: int = 15,
    max_test_chars_per_file: int = 5_000,
    max_rules_chars: int = 10_000,
    include_rules: bool = True,
    workspace_rules_path: Path | None = None,
    workspace_rules_include: list[str] | None = None,
    max_workspace_rules_chars: int = 15_000,
    scope_files: set[str] | None = None,
    max_total_chars: int | None = None,
) -> tuple[str, int]:
    """Aggregate README, impl, tests, and optional rules into a prompt string.

    workspace_rules_path: optional path to parent/workspace .cursor/rules.
    workspace_rules_include: filenames to include; if None/empty, use DEFAULT_WORKSPACE_RULES.
    max_workspace_rules_chars: cap for workspace rules section.
    scope_files: when set, only include these paths (manifests + README always included).
    max_total_chars: when set, stop adding sections once total exceeds this (evict tests first, then impl).

    Returns (prompt_text, total_char_count).
    """
    def in_scope(rel: str) -> bool:
        if scope_files is None:
            return True
        return rel in scope_files

    def would_exceed(add: int) -> bool:
        if max_total_chars is None:
            return False
        return total + add > max_total_chars

    parts: list[str] = []
    total = 0

    # 0. Manifests (entry points, features, deps — reduces false positives)
    for rel in MANIFEST_FILES:
        if rel not in tracked:
            continue
        fp = repo / rel
        if fp.is_file():
            text = _read_file_safe(fp, MANIFEST_MAX_CHARS)
            if text:
                parts.append(f"## Manifest: {rel}\n\n{text}")
                total += len(text)

    # 1. README (always include when in scope)
    readme_paths = [p for p in tracked if _is_readme(p) and in_scope(p)]
    for rel in readme_paths[:3]:  # At most 3 readme-like files
        if would_exceed(max_readme_chars):
            break
        fp = repo / rel
        if fp.is_file():
            text = _read_file_safe(fp, max_readme_chars)
            if text:
                parts.append(f"## README: {rel}\n\n{text}")
                total += len(text)

    # 2. Implementation files
    impl_paths = sorted([p for p in tracked if _is_impl_file(p) and in_scope(p)])[:max_impl_files]
    for rel in impl_paths:
        fp = repo / rel
        if fp.is_file():
            text = _read_file_safe(fp, max_impl_chars_per_file)
            if text and not would_exceed(len(text)):
                parts.append(f"## Implementation: {rel}\n\n{text}")
                total += len(text)
            elif would_exceed(0):
                break

    # 3. Test files (evicted first when near limit)
    test_paths = sorted([p for p in tracked if _is_test_file(p) and in_scope(p)])[:max_test_files]
    for rel in test_paths:
        if would_exceed(max_test_chars_per_file):
            break
        fp = repo / rel
        if fp.is_file():
            text = _read_file_safe(fp, max_test_chars_per_file)
            if text:
                parts.append(f"## Test: {rel}\n\n{text}")
                total += len(text)

    # 4. Per-repo rules (from tracked files)
    if include_rules and not would_exceed(max_rules_chars):
        rules_paths = [p for p in tracked if _is_rules_file(p) and in_scope(p)]
        rules_text: list[str] = []
        rules_chars = 0
        for rel in rules_paths:
            if rules_chars >= max_rules_chars:
                break
            fp = repo / rel
            if fp.is_file():
                text = _read_file_safe(fp, max_rules_chars - rules_chars)
                if text:
                    rules_text.append(f"### {rel}\n\n{text}")
                    rules_chars += len(text)
        if rules_text:
            parts.append("## Project Rules (repo-local)\n\n" + "\n\n".join(rules_text))
            total += rules_chars

    # 5. Workspace rules (opportunistic: when path exists and repo is under it)
    if workspace_rules_path and not would_exceed(max_workspace_rules_chars):
        wr_path = Path(workspace_rules_path).expanduser().resolve()
        if wr_path.is_dir():
            include = workspace_rules_include or DEFAULT_WORKSPACE_RULES
            ws_rules_text: list[str] = []
            ws_chars = 0
            for fname in include:
                if ws_chars >= max_workspace_rules_chars:
                    break
                fp = wr_path / fname
                if fp.is_file():
                    text = _read_file_safe(fp, max_workspace_rules_chars - ws_chars)
                    if text:
                        ws_rules_text.append(f"### {fname}\n\n{text}")
                        ws_chars += len(text)
            if ws_rules_text:
                parts.append(
                    "## Workspace Rules (shared)\n\n" + "\n\n".join(ws_rules_text)
                )
                total += ws_chars

    header = f"# Project: {repo.name}\n\nPath: {repo}\n\n"
    prompt = header + "\n\n---\n\n".join(parts)
    return prompt, total + len(header)


def _try_parse_json(text: str) -> list[FlauditFinding] | None:
    """Attempt to parse text as findings JSON. Returns None on failure."""
    try:
        # Handle markdown code block (```json or ``` json or bare ```)
        if "```" in text:
            parts = text.split("```")
            # Find the first non-empty block after a fence opener
            for i in range(1, len(parts)):
                candidate = parts[i].strip()
                # Strip optional language tag (json, JSON, etc.)
                if candidate.lower().startswith("json"):
                    candidate = candidate[4:].strip()
                if candidate:
                    text = candidate
                    break
        data = json.loads(text)
        if isinstance(data, list):
            items = data
        else:
            items = data.get("findings", data.get("findings_list", []))
        out: list[FlauditFinding] = []
        for item in items:
            if isinstance(item, dict):
                out.append(
                    FlauditFinding(
                        severity=str(item.get("severity", "medium")).lower(),
                        category=str(item.get("category", "other")),
                        description=str(item.get("description", "")),
                        file_ref=item.get("file_ref") or item.get("file"),
                        suggestion=item.get("suggestion"),
                        rule_ref=item.get("rule_ref") or item.get("rule"),
                    )
                )
        return out
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


def _parse_llm_findings(content: str) -> list[FlauditFinding]:
    """Parse LLM JSON response into FlauditFinding list. Retries once on parse failure."""
    findings: list[FlauditFinding] = []
    raw = content

    result = _try_parse_json(raw)
    if result is not None:
        return result
    # Retry: common JSON repair (trailing comma)
    repaired = raw.replace(", ]", "]").replace(", }", "}")
    result = _try_parse_json(repaired)
    if result is not None:
        return result
    # Retry: truncation repair — find last complete {...} object in the array, close JSON.
    # Handles both {"findings": [...]} and bare [...] formats.
    result = _try_truncation_repair(raw)
    if result is not None:
        logger.info("flaudit parse recovered %d findings from truncated JSON", len(result))
        return result
    logger.warning(
        "flaudit parse failed; raw response (truncated): %s",
        (raw[:500] + "..." if len(raw) > 500 else raw),
    )
    return findings


def _find_array_start(raw: str) -> tuple[int, str] | None:
    """Find the start of the findings array and the suffix needed to close the JSON.

    Returns (array_start_index, closing_suffix) or None.
    """
    # {"findings": [...  =>  suffix = "]}"
    if '"findings"' in raw:
        start = raw.find("[", raw.find('"findings"'))
        if start >= 0:
            return start, "]}"
    if '"findings_list"' in raw:
        start = raw.find("[", raw.find('"findings_list"'))
        if start >= 0:
            return start, "]}"
    # Bare list: [...  =>  suffix = "]"
    stripped = raw.lstrip()
    if stripped.startswith("["):
        return raw.index("["), "]"
    return None


def _try_truncation_repair(raw: str) -> list[FlauditFinding] | None:
    """Attempt to recover findings from truncated JSON by closing at the last complete object."""
    loc = _find_array_start(raw)
    if loc is None:
        return None
    start, suffix = loc
    try:
        depth = 0
        last_close = -1
        i = start + 1
        in_string = False
        escape = False
        quote = None
        while i < len(raw):
            c = raw[i]
            if in_string:
                if escape:
                    escape = False
                elif c == "\\":
                    escape = True
                elif c == quote:
                    in_string = False
                i += 1
                continue
            if c in ('"', "'"):
                in_string = True
                quote = c
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    last_close = i
            i += 1
        if last_close > 0:
            repaired = raw[: last_close + 1] + suffix
            return _try_parse_json(repaired)
    except Exception:
        pass
    return None


def scan_project_flaudit(
    dev_root: Path,
    k_recent: int = 5,
    max_depth: int = 2,
    model_id: str = "google/gemini-2.5-flash",
    settings=None,
    max_prompt_chars: int = 120_000,
    include_rules: bool = True,
    exclude_repo_globs: list[str] | None = None,
    workspace_rules_path: str | Path | None = None,
    workspace_rules_include: list[str] | None = None,
    max_workspace_rules_chars: int = 15_000,
    severity_guidance: str | None = None,
    depth_0_skip_prefixes: list[str] | None = None,
    depth_0_allow_names: list[str] | None = None,
    scope_recent_commits: int | None = None,
    public_repo_names: list[str] | None = None,
    stricter_public_prompt: bool = True,
) -> tuple[list[ProjectFlauditResult], dict]:
    """Run flaudit on k most recently edited projects, or only on named public repos.

    When public_repo_names is non-empty, only those repos (by dir name) are analyzed
    and stricter_public_prompt is used. Otherwise k_recent applies. Returns (results, metadata).
    """
    exclude_globs = exclude_repo_globs or [
        "*/_trash/*", "*/_scratch/*", "*/_external/*", "*/_archive/*", "*/_forks/*",
    ]
    repos = _discover_git_repos(
        dev_root,
        max_depth=max_depth,
        depth_0_skip_prefixes=depth_0_skip_prefixes,
        depth_0_allow_names=depth_0_allow_names,
    )

    # Filter by exclude globs
    def excluded(r: Path) -> bool:
        rel = str(r.relative_to(dev_root)) if r.is_relative_to(dev_root) else str(r)
        for g in exclude_globs:
            if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(str(r), f"*{g}"):
                return True
        return False

    repos = [r for r in repos if not excluded(r)]

    if public_repo_names:
        name_set = {n.strip().lower() for n in public_repo_names if n.strip()}
        selected = [r for r in repos if r.name.lower() in name_set][:30]
        public_repo_mode = stricter_public_prompt
    else:
        with_times = [(r, _repo_last_commit_time(r)) for r in repos]
        with_times.sort(key=lambda x: x[1], reverse=True)
        selected = [r for r, _ in with_times[:k_recent]]
        public_repo_mode = False

    results: list[ProjectFlauditResult] = []
    llm_service = None
    if settings and getattr(settings, "openrouter_api_key", None):
        from devguard.llm_service import LLMService
        llm_service = LLMService(settings)

    # Phase 1: build prompts (CPU/IO-bound git work, no async needed).
    pending: list[tuple[Path, str, int]] = []  # (repo, prompt, char_count)
    for repo in selected:
        tracked = _git_ls_files(repo)
        if not tracked:
            results.append(
                ProjectFlauditResult(repo_path=str(repo), prompt_char_count=0, error="no tracked files")
            )
            continue

        scope_files: set[str] | None = None
        if scope_recent_commits and scope_recent_commits > 0:
            recent = _git_files_changed_last_n(repo, scope_recent_commits)
            always = {p for p in tracked if p in MANIFEST_FILES or _is_readme(p)}
            scope_files = recent | always

        wr_path: Path | None = None
        if workspace_rules_path:
            wr_path = Path(workspace_rules_path).expanduser().resolve()
            if not wr_path.is_dir():
                wr_path = None

        prompt, char_count = files_to_prompt(
            repo,
            tracked,
            include_rules=include_rules,
            workspace_rules_path=wr_path,
            workspace_rules_include=workspace_rules_include,
            max_workspace_rules_chars=max_workspace_rules_chars,
            scope_files=scope_files,
            max_total_chars=max_prompt_chars,
        )
        if char_count > max_prompt_chars:
            prompt = prompt[:max_prompt_chars] + "\n\n[... prompt truncated ...]"
            char_count = max_prompt_chars

        if not llm_service:
            results.append(
                ProjectFlauditResult(
                    repo_path=str(repo),
                    prompt_char_count=char_count,
                    error="OPENROUTER_API_KEY not set; skipping LLM analysis",
                )
            )
            continue

        pending.append((repo, prompt, char_count))

    # Phase 2: send all LLM calls concurrently in a single event loop.
    if pending and llm_service:
        async def _run_all() -> list[tuple[Path, int, str | Exception]]:
            """Fire all LLM calls concurrently; return (repo, char_count, raw_response | Exception)."""
            async def _one(repo: Path, prompt: str, cc: int) -> tuple[Path, int, str | Exception]:
                try:
                    raw = await llm_service.analyze_project_flaudit(
                        prompt,
                        model_id=model_id,
                        severity_guidance=severity_guidance,
                        public_repo_mode=public_repo_mode,
                    )
                    return repo, cc, raw
                except Exception as e:
                    return repo, cc, e

            return await asyncio.gather(*[_one(r, p, c) for r, p, c in pending])

        llm_results = asyncio.run(_run_all())
        for repo, char_count, raw_or_err in llm_results:
            if isinstance(raw_or_err, Exception):
                results.append(
                    ProjectFlauditResult(repo_path=str(repo), prompt_char_count=char_count, error=str(raw_or_err))
                )
            else:
                findings = _parse_llm_findings(raw_or_err)
                results.append(
                    ProjectFlauditResult(repo_path=str(repo), prompt_char_count=char_count, findings=findings)
                )

    meta = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dev_root": str(dev_root.expanduser()),
        "repos_scanned": len(selected),
        "k_recent": k_recent,
        "model_id": model_id,
    }
    return results, meta


def write_report(path: Path, results: list[ProjectFlauditResult], meta: dict) -> None:
    """Write flaudit report to JSON."""
    payload = {
        **meta,
        "results": [
            {
                "repo_path": r.repo_path,
                "prompt_char_count": r.prompt_char_count,
                "findings": [asdict(f) for f in r.findings],
                "error": r.error,
            }
            for r in results
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
