"""AI editor config audit: validate Claude, Cursor, Copilot, MCP, and cross-tool configs.

Scans git repos under a dev root for AI coding tool configurations and checks:
- CLAUDE.md presence, case correctness, basic validity
- .claude/ directory (settings.json, rules format, settings.local.json not tracked)
- Cursor rules (.cursor/rules/*.mdc well-formed, .cursorrules)
- Copilot config (.github/copilot-instructions.md)
- MCP configs (.mcp.json, .claude.json -- valid JSON, no hardcoded secrets)
- Cross-tool consistency (same rules expressed across Claude/Cursor)
- Generated file freshness (provenance headers from dotfiles sync)
"""

from __future__ import annotations

import json
import re
import subprocess
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devguard.sweeps._common import default_dev_root as _default_dev_root
from devguard.sweeps._common import iter_git_repos
from devguard.sweeps._common import utc_now as _utc_now


def _is_likely_public(repo: Path) -> bool:
    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"):
        if (repo / name).exists():
            return True
    return False


def _is_tracked_by_git(repo: Path, rel_path: str) -> bool:
    """Check if a file is tracked by git."""
    try:
        res = subprocess.run(
            ["git", "ls-files", rel_path],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=5,
        )
        return bool(res.stdout.strip())
    except Exception:
        return False


def _git_tracks_case(repo: Path, expected: str) -> str | None:
    """Check what case git actually tracks for a file. Returns tracked name or None."""
    try:
        res = subprocess.run(
            ["git", "ls-files", expected],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=5,
        )
        tracked = res.stdout.strip()
        if tracked:
            return tracked
        # Try lowercase variant
        res2 = subprocess.run(
            ["git", "ls-files", expected.lower()],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=5,
        )
        tracked2 = res2.stdout.strip()
        return tracked2 if tracked2 else None
    except Exception:
        return None


# Patterns that look like hardcoded secrets in JSON configs
_SECRET_PATTERNS = [
    # API keys that are 20+ alphanumeric chars (not env var refs)
    re.compile(
        r'"(?:api[_-]?key|token|secret|password|credential)"\s*:\s*"([a-zA-Z0-9_\-]{20,})"',
        re.IGNORECASE,
    ),
    # Bare long hex strings that aren't env refs
    re.compile(r'"[^"]*"\s*:\s*"([0-9a-f]{32,})"', re.IGNORECASE),
]

# Env var reference patterns (these are OK)
_ENV_REF_PATTERNS = [
    re.compile(r"\$\{[A-Z_]+\}"),  # ${VAR}
    re.compile(r"\$\{env:[A-Z_]+\}"),  # ${env:VAR} (windsurf)
    re.compile(r"\$[A-Z_]+"),  # $VAR (gemini)
]

# Unicode codepoints used in prompt injection / Rules File Backdoor attacks.
_SUSPICIOUS_CODEPOINTS: set[int] = (
    {0x200D}  # Zero-width joiner
    | {0x200B, 0xFEFF}  # Zero-width space, BOM
    | {0x200C}  # Zero-width non-joiner
    | set(range(0x202A, 0x202E + 1))  # Bidi overrides (LRE, RLE, PDF, LRO, RLO)
    | set(range(0x2066, 0x2069 + 1))  # Bidi isolates (LRI, RLI, FSI, PDI)
    | set(range(0xE0001, 0xE007F + 1))  # Tag characters
    | set(range(0xFE00, 0xFE0F + 1))  # Variation selectors
)

# AI editor config/rules files to scan for unicode injection per repo.
_UNICODE_SCAN_PATHS: list[str] = [
    ".cursorrules",
    "CLAUDE.md",
    ".github/copilot-instructions.md",
]
_UNICODE_SCAN_GLOBS: list[tuple[str, str]] = [
    (".cursor/rules", "*.md"),
    (".cursor/rules", "*.mdc"),
    (".claude/rules", "*.md"),
]


def _check_unicode_injection(file_path: Path) -> list[dict[str, object]]:
    """Scan a file for suspicious invisible Unicode characters (prompt injection indicators).

    Returns a list of finding dicts (check, severity, file, line, message, context).
    """
    findings: list[dict[str, object]] = []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    for line_no, line in enumerate(text.splitlines(), start=1):
        for col, ch in enumerate(line):
            cp = ord(ch)
            if cp not in _SUSPICIOUS_CODEPOINTS:
                continue
            # Build Unicode name or hex fallback
            try:
                cp_name = unicodedata.name(ch)
            except ValueError:
                cp_name = f"U+{cp:04X}"
            # Surrounding context: 5 chars before/after with the invisible char replaced
            before = line[max(0, col - 5) : col]
            after = line[col + 1 : col + 6]
            marker = f"[U+{cp:04X}]"
            context = f"...{before}{marker}{after}..."
            findings.append(
                {
                    "check": "unicode_injection",
                    "severity": "error",
                    "file": str(file_path),
                    "line": line_no,
                    "message": (
                        f"Invisible Unicode character U+{cp:04X} ({cp_name}) "
                        f"found -- possible prompt injection"
                    ),
                    "context": context,
                }
            )
    return findings


@dataclass
class Finding:
    check: str
    severity: str  # "error", "warning", "info"
    message: str
    detail: str = ""


@dataclass
class RepoAuditResult:
    repo_path: str
    repo_name: str
    is_public: bool
    has_claude_md: bool = False
    has_claude_dir: bool = False
    has_cursor_rules: bool = False
    has_copilot_config: bool = False
    has_mcp_config: bool = False
    ai_tools_detected: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def _check_claude_md(repo: Path, result: RepoAuditResult) -> None:
    """Check CLAUDE.md presence and correctness."""
    claude_md = repo / "CLAUDE.md"
    claude_dir_md = repo / ".claude" / "CLAUDE.md"

    # Check case sensitivity
    tracked = _git_tracks_case(repo, "CLAUDE.md")
    if tracked and tracked != "CLAUDE.md":
        result.findings.append(
            Finding(
                check="claude_md_case",
                severity="error",
                message=f"Git tracks '{tracked}' but Claude Code expects 'CLAUDE.md'",
                detail="On case-insensitive filesystems (macOS), wrong case works locally but breaks on Linux/CI",
            )
        )

    if claude_md.is_file():
        result.has_claude_md = True
        result.ai_tools_detected.append("claude")
        try:
            text = claude_md.read_text(encoding="utf-8", errors="replace")
            if not text.strip():
                result.findings.append(
                    Finding(
                        check="claude_md_empty",
                        severity="warning",
                        message="CLAUDE.md exists but is empty",
                    )
                )
            elif len(text) > 50_000:
                result.findings.append(
                    Finding(
                        check="claude_md_large",
                        severity="info",
                        message=f"CLAUDE.md is {len(text)} chars (may hit context limits)",
                    )
                )
        except Exception:
            pass
    elif claude_dir_md.is_file():
        result.has_claude_md = True
        result.ai_tools_detected.append("claude")


def _check_claude_dir(repo: Path, result: RepoAuditResult) -> None:
    """Check .claude/ directory structure."""
    claude_dir = repo / ".claude"
    if not claude_dir.is_dir():
        return
    result.has_claude_dir = True

    # Check settings.json validity
    settings = claude_dir / "settings.json"
    if settings.is_file():
        try:
            text = settings.read_text(encoding="utf-8", errors="replace")
            json.loads(text)
        except json.JSONDecodeError as e:
            result.findings.append(
                Finding(
                    check="claude_settings_invalid",
                    severity="error",
                    message=f".claude/settings.json is invalid JSON: {e}",
                )
            )

    # Check settings.local.json not tracked
    local_settings = claude_dir / "settings.local.json"
    if local_settings.is_file():
        if _is_tracked_by_git(repo, ".claude/settings.local.json"):
            result.findings.append(
                Finding(
                    check="claude_local_settings_tracked",
                    severity="error",
                    message=".claude/settings.local.json is tracked by git",
                    detail="This file may contain machine-specific or work-specific secrets. "
                    "Add to .gitignore: .claude/settings.local.json",
                )
            )

    # Check rules files
    rules_dir = claude_dir / "rules"
    if rules_dir.is_dir():
        for f in sorted(rules_dir.iterdir()):
            if not f.is_file() or f.suffix != ".md":
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
                # Check for paths: frontmatter (glob-triggered rules)
                if text.startswith("---"):
                    end = text.find("---", 3)
                    if end == -1:
                        result.findings.append(
                            Finding(
                                check="claude_rule_bad_frontmatter",
                                severity="warning",
                                message=f".claude/rules/{f.name}: unclosed frontmatter",
                            )
                        )
                if not text.strip():
                    result.findings.append(
                        Finding(
                            check="claude_rule_empty",
                            severity="warning",
                            message=f".claude/rules/{f.name}: empty rule file",
                        )
                    )
            except Exception:
                pass


def _check_cursor_rules(repo: Path, result: RepoAuditResult) -> None:
    """Check Cursor configuration."""
    cursor_rules_dir = repo / ".cursor" / "rules"
    cursorrules_file = repo / ".cursorrules"

    has_rules_dir = cursor_rules_dir.is_dir()
    has_cursorrules = cursorrules_file.is_file()

    if has_rules_dir or has_cursorrules:
        result.has_cursor_rules = True
        if "cursor" not in result.ai_tools_detected:
            result.ai_tools_detected.append("cursor")

    # Warn about deprecated .cursorrules if .cursor/rules/ also exists
    if has_cursorrules and has_rules_dir:
        result.findings.append(
            Finding(
                check="cursor_duplicate_rules",
                severity="warning",
                message="Both .cursorrules and .cursor/rules/ exist",
                detail=".cursorrules is deprecated; migrate to .cursor/rules/",
            )
        )

    # Check if .cursor/rules/ files are tracked by git (they shouldn't be)
    if has_rules_dir:
        tracked_cursor_files = []
        for f in sorted(cursor_rules_dir.iterdir()):
            if f.is_file() and _is_tracked_by_git(repo, f".cursor/rules/{f.name}"):
                tracked_cursor_files.append(f.name)
        if tracked_cursor_files:
            result.findings.append(
                Finding(
                    check="cursor_rules_tracked",
                    severity="error",
                    message=f".cursor/rules/ has {len(tracked_cursor_files)} file(s) tracked by git",
                    detail="Cursor rules are personal/machine-local and should not be committed. "
                    f"Add .cursor/ to .gitignore and run: git rm -r --cached .cursor/rules/. "
                    f"Files: {', '.join(tracked_cursor_files[:10])}",
                )
            )

    if has_rules_dir:
        for f in sorted(cursor_rules_dir.iterdir()):
            if not f.is_file():
                continue
            if f.suffix not in (".mdc", ".md"):
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
                # .mdc files should have YAML frontmatter
                if f.suffix == ".mdc":
                    if not text.startswith("---"):
                        result.findings.append(
                            Finding(
                                check="cursor_mdc_no_frontmatter",
                                severity="warning",
                                message=f".cursor/rules/{f.name}: .mdc file missing frontmatter",
                                detail="Cursor .mdc rules need ---\\ndescription: ...\\nalwaysApply: true/false\\n---",
                            )
                        )
                    else:
                        end = text.find("---", 3)
                        if end == -1:
                            result.findings.append(
                                Finding(
                                    check="cursor_mdc_bad_frontmatter",
                                    severity="warning",
                                    message=f".cursor/rules/{f.name}: unclosed frontmatter",
                                )
                            )
                        else:
                            fm = text[3:end].strip()
                            if "description:" not in fm:
                                result.findings.append(
                                    Finding(
                                        check="cursor_mdc_no_description",
                                        severity="info",
                                        message=f".cursor/rules/{f.name}: missing description in frontmatter",
                                    )
                                )
                            if "alwaysApply:" not in fm:
                                result.findings.append(
                                    Finding(
                                        check="cursor_mdc_no_always_apply",
                                        severity="info",
                                        message=f".cursor/rules/{f.name}: missing alwaysApply in frontmatter",
                                    )
                                )
                if not text.strip():
                    result.findings.append(
                        Finding(
                            check="cursor_rule_empty",
                            severity="warning",
                            message=f".cursor/rules/{f.name}: empty rule file",
                        )
                    )
            except Exception:
                pass


def _check_copilot_config(repo: Path, result: RepoAuditResult) -> None:
    """Check GitHub Copilot configuration."""
    copilot_instructions = repo / ".github" / "copilot-instructions.md"
    if copilot_instructions.is_file():
        result.has_copilot_config = True
        if "copilot" not in result.ai_tools_detected:
            result.ai_tools_detected.append("copilot")
        try:
            text = copilot_instructions.read_text(encoding="utf-8", errors="replace")
            if not text.strip():
                result.findings.append(
                    Finding(
                        check="copilot_instructions_empty",
                        severity="warning",
                        message=".github/copilot-instructions.md exists but is empty",
                    )
                )
        except Exception:
            pass


def _check_mcp_configs(repo: Path, result: RepoAuditResult) -> None:
    """Check MCP server configurations for validity and secret hygiene."""
    mcp_files = [
        (".mcp.json", "mcp"),
        (".claude.json", "claude"),
    ]
    for filename, tool in mcp_files:
        mcp_path = repo / filename
        if not mcp_path.is_file():
            continue
        result.has_mcp_config = True
        if tool not in result.ai_tools_detected:
            result.ai_tools_detected.append(tool)

        try:
            text = mcp_path.read_text(encoding="utf-8", errors="replace")
            try:
                data = json.loads(text)
            except json.JSONDecodeError as e:
                result.findings.append(
                    Finding(
                        check="mcp_invalid_json",
                        severity="error",
                        message=f"{filename}: invalid JSON: {e}",
                    )
                )
                continue

            # Check for hardcoded secrets
            for pattern in _SECRET_PATTERNS:
                for match in pattern.finditer(text):
                    value = match.group(1)
                    # Skip if it looks like an env var reference
                    if any(p.search(value) for p in _ENV_REF_PATTERNS):
                        continue
                    # Skip common non-secret values
                    if value in ("true", "false", "null") or value.startswith("http"):
                        continue
                    result.findings.append(
                        Finding(
                            check="mcp_hardcoded_secret",
                            severity="error",
                            message=f"{filename}: possible hardcoded secret/token",
                            detail="Use ${VAR} env var references instead of literal values. "
                            "Keep secrets in machine-local settings, not tracked files.",
                        )
                    )
                    break  # one finding per file is enough

            # Check that mcpServers entries have required fields
            servers = data.get("mcpServers", {})
            for name, config in servers.items():
                if not isinstance(config, dict):
                    result.findings.append(
                        Finding(
                            check="mcp_server_not_object",
                            severity="error",
                            message=f"{filename}: server '{name}' config is not an object",
                        )
                    )
                    continue
                if "command" not in config and "url" not in config:
                    result.findings.append(
                        Finding(
                            check="mcp_server_no_entrypoint",
                            severity="warning",
                            message=f"{filename}: server '{name}' has no 'command' or 'url'",
                        )
                    )
        except Exception:
            pass

    # Also check .cursor/mcp.json
    cursor_mcp = repo / ".cursor" / "mcp.json"
    if cursor_mcp.is_file():
        result.has_mcp_config = True
        try:
            text = cursor_mcp.read_text(encoding="utf-8", errors="replace")
            json.loads(text)
        except json.JSONDecodeError as e:
            result.findings.append(
                Finding(
                    check="mcp_invalid_json",
                    severity="error",
                    message=f".cursor/mcp.json: invalid JSON: {e}",
                )
            )


def _check_cross_tool_consistency(repo: Path, result: RepoAuditResult) -> None:
    """Check for consistency between Claude and Cursor rule sets."""
    claude_rules_dir = repo / ".claude" / "rules"
    cursor_rules_dir = repo / ".cursor" / "rules"

    if not claude_rules_dir.is_dir() or not cursor_rules_dir.is_dir():
        return

    # Get rule names (strip extensions)
    claude_names: set[str] = set()
    for f in claude_rules_dir.iterdir():
        if f.is_file() and f.suffix == ".md":
            claude_names.add(f.stem)

    cursor_names: set[str] = set()
    for f in cursor_rules_dir.iterdir():
        if f.is_file() and f.suffix in (".mdc", ".md"):
            cursor_names.add(f.stem)

    # Rules that exist in one but not the other
    # Only flag if both tools are in use and there's a meaningful gap
    claude_only = claude_names - cursor_names
    cursor_only = cursor_names - claude_names

    # Skip tool-specific rules (e.g., skill-triggers is Claude-only)
    claude_specific = {"skill-triggers"}
    claude_only -= claude_specific

    if claude_only and cursor_only:
        result.findings.append(
            Finding(
                check="cross_tool_rule_drift",
                severity="info",
                message=f"Rule sets differ: claude-only={sorted(claude_only)}, cursor-only={sorted(cursor_only)}",
                detail="If a rule applies to both tools, sync via dotfiles rules.toml manifest",
            )
        )


def _check_gitignore_coverage(repo: Path, result: RepoAuditResult) -> None:
    """Check if AI config files that should be ignored are in .gitignore."""
    gi_path = repo / ".gitignore"
    if not gi_path.is_file():
        return
    try:
        gi_text = gi_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return

    gi_lines = {
        line.strip().lstrip("/").rstrip("/")
        for line in gi_text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }

    # .claude/settings.local.json should be ignored
    if (repo / ".claude").is_dir():
        local_patterns = {".claude/settings.local.json", ".claude/settings.local.*"}
        if not any(p.rstrip("/") in gi_lines for p in local_patterns):
            # Check if broader .claude/ pattern covers it
            if ".claude" not in gi_lines and ".claude/" not in gi_lines:
                if (repo / ".claude" / "settings.local.json").exists():
                    result.findings.append(
                        Finding(
                            check="gitignore_missing_local_settings",
                            severity="warning",
                            message=".claude/settings.local.json exists but not in .gitignore",
                        )
                    )


def _check_unicode_injection_repo(repo: Path, result: RepoAuditResult) -> None:
    """Scan AI editor config files in a repo for invisible Unicode prompt injection."""
    # Fixed paths
    for rel in _UNICODE_SCAN_PATHS:
        fpath = repo / rel
        if fpath.is_file():
            for raw in _check_unicode_injection(fpath):
                result.findings.append(
                    Finding(
                        check=raw["check"],  # type: ignore[arg-type]
                        severity=raw["severity"],  # type: ignore[arg-type]
                        message=raw["message"],  # type: ignore[arg-type]
                        detail=f"file={raw['file']} line={raw['line']} context={raw['context']}",
                    )
                )

    # Glob-matched paths
    for parent_rel, glob_pat in _UNICODE_SCAN_GLOBS:
        parent = repo / parent_rel
        if not parent.is_dir():
            continue
        for fpath in sorted(parent.glob(glob_pat)):
            if not fpath.is_file():
                continue
            for raw in _check_unicode_injection(fpath):
                result.findings.append(
                    Finding(
                        check=raw["check"],  # type: ignore[arg-type]
                        severity=raw["severity"],  # type: ignore[arg-type]
                        message=raw["message"],  # type: ignore[arg-type]
                        detail=f"file={raw['file']} line={raw['line']} context={raw['context']}",
                    )
                )


def _check_memory_dir(repo: Path, result: RepoAuditResult) -> None:
    """Check for in-repo memory/ directories (should use ~/.claude/projects/ instead)."""
    memory_dir = repo / "memory"
    if not memory_dir.is_dir():
        return
    # Check if any files inside are tracked by git
    try:
        res = subprocess.run(
            ["git", "ls-files", "memory/"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=5,
        )
        tracked = [f for f in res.stdout.strip().splitlines() if f]
    except Exception:
        tracked = []
    if tracked:
        result.findings.append(
            Finding(
                check="memory_dir_tracked",
                severity="warning",
                message=f"memory/ has {len(tracked)} file(s) tracked by git",
                detail="Claude auto-memory belongs in ~/.claude/projects/, not inside repos. "
                "Add memory/ to .gitignore and run: git rm -r --cached memory/",
            )
        )
    elif any(memory_dir.iterdir()):
        # Untracked but present -- info-level (gitignore should catch it)
        result.findings.append(
            Finding(
                check="memory_dir_present",
                severity="info",
                message="memory/ directory exists (untracked)",
                detail="Verify ~/.gitignore_global includes memory/ to prevent accidental commits",
            )
        )


def _check_aider_artifacts(repo: Path, result: RepoAuditResult) -> None:
    """Check if .aider* files are tracked by git."""
    try:
        res = subprocess.run(
            ["git", "ls-files", ".aider*"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=5,
        )
        tracked = [f for f in res.stdout.strip().splitlines() if f]
    except Exception:
        tracked = []
    if tracked:
        result.findings.append(
            Finding(
                check="aider_artifacts_tracked",
                severity="warning",
                message=f"{len(tracked)} .aider* file(s) tracked by git -- add .aider* to .gitignore",
                detail=f"Files: {', '.join(tracked[:10])}",
            )
        )


def _check_skill_case(repo: Path, result: RepoAuditResult) -> None:
    """Check that skills use SKILL.md (uppercase) not skill.md (lowercase)."""
    skills_dir = repo / ".claude" / "skills"
    if not skills_dir.is_dir():
        return
    for subdir in sorted(skills_dir.iterdir()):
        if not subdir.is_dir():
            continue
        has_upper = (subdir / "SKILL.md").exists()
        has_lower = (subdir / "skill.md").exists()
        if has_lower and not has_upper:
            result.findings.append(
                Finding(
                    check="skill_md_case",
                    severity="error",
                    message=f".claude/skills/{subdir.name}/skill.md (lowercase) is not discovered by Claude Code -- rename to SKILL.md",
                )
            )


def _check_dangling_at_refs(repo: Path, result: RepoAuditResult) -> None:
    """Check CLAUDE.md for @path references that point to non-existent files."""
    claude_md = repo / "CLAUDE.md"
    if not claude_md.is_file():
        claude_md = repo / ".claude" / "CLAUDE.md"
        if not claude_md.is_file():
            return
    try:
        text = claude_md.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return

    at_ref_re = re.compile(r"^@(\S+)", re.MULTILINE)
    for match in at_ref_re.finditer(text):
        raw_path = match.group(1)
        expanded = Path(raw_path).expanduser()
        if not expanded.is_absolute():
            expanded = repo / expanded
        if not expanded.exists():
            result.findings.append(
                Finding(
                    check="claude_md_dangling_ref",
                    severity="warning",
                    message=f"CLAUDE.md references @{raw_path} but file does not exist",
                )
            )


def _check_mcp_in_settings(repo: Path, result: RepoAuditResult) -> None:
    """Check if .claude/settings.json contains mcpServers (silently ignored)."""
    settings = repo / ".claude" / "settings.json"
    if not settings.is_file():
        return
    try:
        data = json.loads(settings.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return
    if "mcpServers" in data:
        result.findings.append(
            Finding(
                check="mcp_in_settings_json",
                severity="warning",
                message=".claude/settings.json has mcpServers -- these are silently ignored. Move to .mcp.json or ~/.claude.json",
            )
        )


def _check_cursorrules_public(repo: Path, result: RepoAuditResult) -> None:
    """Check if .cursorrules is tracked in a public repo."""
    if not result.is_public:
        return
    if _is_tracked_by_git(repo, ".cursorrules"):
        result.findings.append(
            Finding(
                check="cursorrules_tracked_public",
                severity="warning",
                message=".cursorrules is tracked in a public repo -- may leak internal coding instructions",
            )
        )


def _audit_repo(repo: Path) -> RepoAuditResult:
    """Run all AI editor config checks on a single repo."""
    result = RepoAuditResult(
        repo_path=str(repo),
        repo_name=repo.name,
        is_public=_is_likely_public(repo),
    )

    _check_claude_md(repo, result)
    _check_claude_dir(repo, result)
    _check_cursor_rules(repo, result)
    _check_copilot_config(repo, result)
    _check_mcp_configs(repo, result)
    _check_cross_tool_consistency(repo, result)
    _check_gitignore_coverage(repo, result)
    _check_unicode_injection_repo(repo, result)
    _check_memory_dir(repo, result)
    _check_aider_artifacts(repo, result)
    _check_skill_case(repo, result)
    _check_dangling_at_refs(repo, result)
    _check_mcp_in_settings(repo, result)
    _check_cursorrules_public(repo, result)

    return result


def audit_ai_editor_configs(
    *,
    dev_root: Path | None = None,
    max_depth: int = 2,
    exclude_repo_globs: list[str] | None = None,
    only_with_configs: bool = True,
) -> tuple[dict[str, Any], list[str]]:
    """Audit AI editor configurations across repos and return a report."""
    errors: list[str] = []
    root = dev_root if dev_root is not None else _default_dev_root()
    globs = [g for g in (exclude_repo_globs or []) if isinstance(g, str) and g.strip()]

    repos = sorted(iter_git_repos(root, max_depth=max_depth, exclude_globs=globs))

    results: list[RepoAuditResult] = []
    for repo in repos:
        try:
            result = _audit_repo(repo)
            results.append(result)
        except Exception as exc:
            errors.append(f"failed to audit {repo}: {exc}")

    # Filter to repos with AI configs if requested
    if only_with_configs:
        results = [r for r in results if r.ai_tools_detected]

    # Sort: public repos with errors first
    results.sort(
        key=lambda r: (
            -r.is_public,
            -sum(1 for f in r.findings if f.severity == "error"),
            -sum(1 for f in r.findings if f.severity == "warning"),
            r.repo_name,
        )
    )

    # Summary
    repos_with_errors = [r for r in results if any(f.severity == "error" for f in r.findings)]
    repos_with_warnings = [r for r in results if any(f.severity == "warning" for f in r.findings)]
    tool_counts: dict[str, int] = {}
    for r in results:
        for tool in r.ai_tools_detected:
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
    check_counts: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            check_counts[f.check] = check_counts.get(f.check, 0) + 1

    repos_without_any_config = sum(1 for r in results if not r.ai_tools_detected)

    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {
            "dev_root": str(root),
            "repos_scanned": len(repos),
            "repos_with_ai_configs": len([r for r in results if r.ai_tools_detected]),
            "max_depth": max_depth,
            "only_with_configs": only_with_configs,
            "exclude_repo_globs": globs,
        },
        "summary": {
            "repos_with_errors": len(repos_with_errors),
            "repos_with_errors_list": [r.repo_name for r in repos_with_errors],
            "repos_with_warnings": len(repos_with_warnings),
            "repos_with_warnings_list": [r.repo_name for r in repos_with_warnings],
            "total_findings": sum(len(r.findings) for r in results),
            "findings_by_check": sorted(check_counts.items(), key=lambda x: -x[1]),
            "total_errors": sum(1 for r in results for f in r.findings if f.severity == "error"),
            "total_warnings": sum(
                1 for r in results for f in r.findings if f.severity == "warning"
            ),
            "tool_adoption": sorted(tool_counts.items(), key=lambda x: -x[1]),
            "repos_without_any_config": repos_without_any_config,
        },
        "repos": [
            {
                "repo_path": r.repo_path,
                "repo_name": r.repo_name,
                "is_public": r.is_public,
                "ai_tools": r.ai_tools_detected,
                "findings": [
                    {
                        "check": f.check,
                        "severity": f.severity,
                        "message": f.message,
                        **({"detail": f.detail} if f.detail else {}),
                    }
                    for f in r.findings
                ],
            }
            for r in results
            if r.findings
        ][:200],
        "clean_repos": [r.repo_name for r in results if r.ai_tools_detected and not r.findings],
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
