"""MCP security audit: deep config scanning for hardcoded secrets, injection, and trifecta risk.

Complements the basic MCP JSON validity checks in ai_editor_config_audit with
security-focused analysis: provider-specific secret patterns, shell injection in
command/args, lethal trifecta detection, env literal hygiene, and git-tracking of
secret-bearing configs.

Research backing: 88% of MCP servers require credentials, 53% use static secrets
(Astrix Security). 48% recommend plaintext .env (Trend Micro). First SoK on MCP
security (arXiv 2512.08290). OWASP Agentic Top 10 ASI04.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from devguard.sweeps._common import default_dev_root as _default_dev_root
from devguard.sweeps._common import iter_git_repos, utc_now as _utc_now

# ---------------------------------------------------------------------------
# Secret detection patterns
# ---------------------------------------------------------------------------

# Provider-specific prefixes that are sufficient to flag on their own.
_PROVIDER_SECRET_PREFIXES: list[str] = [
    "ghp_",       # GitHub PAT (fine-grained)
    "gho_",       # GitHub OAuth
    "ghu_",       # GitHub user-to-server
    "ghs_",       # GitHub server-to-server
    "github_pat_",  # GitHub PAT (new format)
    "sk-ant-",    # Anthropic
    "sk-proj-",   # OpenAI project key
    "sk-",        # OpenAI (legacy; 20+ chars after prefix)
    "AKIA",       # AWS access key ID
    "xoxb-",      # Slack bot token
    "xoxp-",      # Slack user token
    "xoxa-",      # Slack app token
    "sk_live_",   # Stripe live key
    "rk_live_",   # Stripe restricted key
    "npm_",       # npm token
    "pypi-",      # PyPI token
    "glpat-",     # GitLab PAT
    "hf_",        # HuggingFace
]

# Compiled prefix regex (match at start of value).
_PROVIDER_RE = re.compile(
    r"^(" + "|".join(re.escape(p) for p in _PROVIDER_SECRET_PREFIXES) + r")\S{8,}",
)

# Generic long hex/base64 -- only fire when the *key name* suggests a secret.
_SECRET_KEY_NAMES = re.compile(
    r"(?:api[_-]?key|token|secret|password|credential|auth)",
    re.IGNORECASE,
)
_LONG_HEX_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
_LONG_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]{40,}$")

# Env var reference patterns (these are OK).
_ENV_REF_RE = re.compile(r"\$\{[^}]+\}")

# Placeholder patterns (acceptable non-secrets).
_PLACEHOLDER_RES: list[re.Pattern[str]] = [
    re.compile(r"^xxx", re.IGNORECASE),
    re.compile(r"^your[_-]", re.IGNORECASE),
    re.compile(r"^<.*>$"),
    re.compile(r"^changeme$", re.IGNORECASE),
    re.compile(r"^CHANGE_ME$", re.IGNORECASE),
    re.compile(r"^TODO", re.IGNORECASE),
    re.compile(r"^replace[_-]", re.IGNORECASE),
    re.compile(r"^insert[_-]", re.IGNORECASE),
    re.compile(r"^my[_-]", re.IGNORECASE),
    re.compile(r"^\.\.\.$"),
]

# ---------------------------------------------------------------------------
# Command injection patterns
# ---------------------------------------------------------------------------

_SHELL_META_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\$\("),       # command substitution
    re.compile(r"`"),          # backtick substitution
    re.compile(r"\|"),         # pipe
    re.compile(r";"),          # command separator
    re.compile(r"&&"),         # logical AND
    re.compile(r">>"),         # append redirect
]

# ---------------------------------------------------------------------------
# Lethal trifecta servers: private data + untrusted input + external comms
# ---------------------------------------------------------------------------

_TRIFECTA_SERVER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"github", re.IGNORECASE),
    re.compile(r"slack", re.IGNORECASE),
    re.compile(r"email", re.IGNORECASE),
    re.compile(r"gmail", re.IGNORECASE),
    re.compile(r"outlook", re.IGNORECASE),
    re.compile(r"linear", re.IGNORECASE),
    re.compile(r"jira", re.IGNORECASE),
    re.compile(r"notion", re.IGNORECASE),
    re.compile(r"confluence", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# MCP config file locations
# ---------------------------------------------------------------------------

# Per-repo config files (relative to repo root).
_REPO_MCP_FILES: list[str] = [
    ".mcp.json",
    ".cursor/mcp.json",
    ".claude.json",
    "mcp-manifest.json",
]

# User-level config files (absolute, expanded at runtime).
def _user_mcp_files() -> list[Path]:
    home = Path.home()
    paths = [
        home / ".claude" / "settings.json",
        home / ".cursor" / "mcp.json",
    ]
    # macOS Claude desktop config
    app_support = home / "Library" / "Application Support" / "Claude"
    paths.append(app_support / "claude_desktop_config.json")
    return paths


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_env_ref(value: str) -> bool:
    """True if the value is an env var reference like ${FOO}."""
    return bool(_ENV_REF_RE.fullmatch(value.strip()))


def _is_placeholder(value: str) -> bool:
    """True if the value matches a known placeholder pattern."""
    return any(p.search(value) for p in _PLACEHOLDER_RES)


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


def _check_value_for_secret(key_name: str, value: str) -> str | None:
    """Return a check_id if value looks like a hardcoded secret, else None."""
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()

    # Skip env var references and placeholders.
    if _is_env_ref(v) or _is_placeholder(v):
        return None

    # Provider-specific prefix match -- fires regardless of key name.
    if _PROVIDER_RE.match(v):
        return "mcp_hardcoded_secret"

    # Generic long hex/base64 -- only if key name is secret-like.
    if _SECRET_KEY_NAMES.search(key_name):
        if _LONG_HEX_RE.match(v) or _LONG_BASE64_RE.match(v):
            return "mcp_hardcoded_secret"

    return None


def _check_command_injection(parts: list[str]) -> bool:
    """True if any part contains shell metacharacters."""
    for part in parts:
        for pattern in _SHELL_META_PATTERNS:
            if pattern.search(part):
                return True
    return False


def _extract_url_domain(url: str) -> str | None:
    """Extract domain from a URL string."""
    m = re.match(r"https?://([^/:]+)", url)
    return m.group(1) if m else None


def _is_trifecta_server(name: str) -> bool:
    """True if server name matches a known trifecta-capable service."""
    return any(p.search(name) for p in _TRIFECTA_SERVER_PATTERNS)


# ---------------------------------------------------------------------------
# Per-config analysis
# ---------------------------------------------------------------------------

def _audit_mcp_config(
    config_path: Path,
    *,
    repo_root: Path | None,
    trusted_domains: list[str],
) -> list[dict[str, Any]]:
    """Audit a single MCP config file. Returns list of finding dicts."""
    findings: list[dict[str, Any]] = []
    rel_label = str(config_path)
    if repo_root and str(config_path).startswith(str(repo_root)):
        rel_label = str(config_path.relative_to(repo_root))

    try:
        text = config_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return findings

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Invalid JSON is already covered by ai_editor_config_audit; skip here.
        return findings

    if not isinstance(data, dict):
        return findings

    # Locate mcpServers block -- top-level or nested.
    servers: dict[str, Any] = {}
    if "mcpServers" in data and isinstance(data["mcpServers"], dict):
        servers = data["mcpServers"]
    else:
        # Some formats put servers at the root level with command/url fields.
        for k, v in data.items():
            if isinstance(v, dict) and ("command" in v or "url" in v or "args" in v):
                servers[k] = v

    has_any_secret = False

    for server_name, server_cfg in servers.items():
        if not isinstance(server_cfg, dict):
            continue

        # --- mcp_hardcoded_secret: check env block values ---
        env_block = server_cfg.get("env", {})
        if isinstance(env_block, dict):
            for env_key, env_val in env_block.items():
                if not isinstance(env_val, str):
                    continue
                check = _check_value_for_secret(env_key, env_val)
                if check and not has_any_secret:
                    findings.append({
                        "check_id": "mcp_hardcoded_secret",
                        "severity": "error",
                        "file": rel_label,
                        "server": server_name,
                        "message": (
                            f"Hardcoded secret in env.{env_key} for server '{server_name}' "
                            f"-- use ${{VAR}} env var reference instead"
                        ),
                    })
                    has_any_secret = True

                # --- mcp_env_literal: literal string instead of ${VAR} ---
                if not _is_env_ref(env_val) and not _is_placeholder(env_val):
                    findings.append({
                        "check_id": "mcp_env_literal",
                        "severity": "warning",
                        "file": rel_label,
                        "server": server_name,
                        "message": (
                            f"env.{env_key} for server '{server_name}' is a literal "
                            f"string, not a ${{VAR}} reference"
                        ),
                    })

        # --- mcp_hardcoded_secret: check args for secrets ---
        args = server_cfg.get("args", [])
        if isinstance(args, list):
            for arg in args:
                if not isinstance(arg, str):
                    continue
                check = _check_value_for_secret("arg", arg)
                if check and not has_any_secret:
                    findings.append({
                        "check_id": "mcp_hardcoded_secret",
                        "severity": "error",
                        "file": rel_label,
                        "server": server_name,
                        "message": (
                            f"Hardcoded secret in args for server '{server_name}' "
                            f"-- use env var reference instead"
                        ),
                    })
                    has_any_secret = True

        # --- mcp_command_injection ---
        cmd_parts: list[str] = []
        cmd = server_cfg.get("command")
        if isinstance(cmd, str):
            cmd_parts.append(cmd)
        if isinstance(args, list):
            cmd_parts.extend(str(a) for a in args if isinstance(a, str))
        if cmd_parts and _check_command_injection(cmd_parts):
            findings.append({
                "check_id": "mcp_command_injection",
                "severity": "error",
                "file": rel_label,
                "server": server_name,
                "message": (
                    f"Shell metacharacters in command/args for server '{server_name}' "
                    f"-- possible command injection"
                ),
            })

        # --- mcp_untrusted_url ---
        url = server_cfg.get("url")
        if isinstance(url, str):
            domain = _extract_url_domain(url)
            if domain and domain not in trusted_domains:
                findings.append({
                    "check_id": "mcp_untrusted_url",
                    "severity": "warning",
                    "file": rel_label,
                    "server": server_name,
                    "message": (
                        f"Server '{server_name}' URL points to '{domain}' "
                        f"which is not in trusted_domains"
                    ),
                })

        # --- mcp_lethal_trifecta ---
        if _is_trifecta_server(server_name):
            findings.append({
                "check_id": "mcp_lethal_trifecta",
                "severity": "error",
                "file": rel_label,
                "server": server_name,
                "message": (
                    f"Server '{server_name}' matches a known trifecta-capable service "
                    f"(private data + untrusted input + external communication)"
                ),
            })

    # --- mcp_config_in_git: check if this config is tracked ---
    if repo_root and has_any_secret:
        try:
            rel_to_repo = str(config_path.relative_to(repo_root))
            if _is_tracked_by_git(repo_root, rel_to_repo):
                findings.append({
                    "check_id": "mcp_config_in_git",
                    "severity": "warning",
                    "file": rel_label,
                    "server": "(all)",
                    "message": (
                        f"MCP config '{rel_to_repo}' containing secrets is tracked by git"
                    ),
                })
        except ValueError:
            pass

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def audit_mcp_security(
    *,
    dev_root: Path | None = None,
    max_depth: int = 2,
    exclude_repo_globs: list[str] | None = None,
    check_user_configs: bool = True,
    trusted_domains: list[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Audit MCP configurations for security issues across repos and user configs.

    Returns (report_dict, errors_list).
    """
    errors: list[str] = []
    root = dev_root if dev_root is not None else _default_dev_root()
    globs = [g for g in (exclude_repo_globs or []) if isinstance(g, str) and g.strip()]
    domains = trusted_domains if trusted_domains is not None else ["localhost", "127.0.0.1"]

    all_findings: list[dict[str, Any]] = []
    configs_scanned = 0
    repos_scanned = 0

    # --- Per-repo MCP configs ---
    repos = sorted(iter_git_repos(root, max_depth=max_depth, exclude_globs=globs))
    repos_scanned = len(repos)

    for repo in repos:
        for rel_path in _REPO_MCP_FILES:
            config_path = repo / rel_path
            if not config_path.is_file():
                continue
            configs_scanned += 1
            try:
                findings = _audit_mcp_config(
                    config_path,
                    repo_root=repo,
                    trusted_domains=domains,
                )
                all_findings.extend(findings)
            except Exception as exc:
                errors.append(f"failed to audit {config_path}: {exc}")

    # --- User-level MCP configs ---
    user_configs_scanned = 0
    if check_user_configs:
        for config_path in _user_mcp_files():
            if not config_path.is_file():
                continue
            user_configs_scanned += 1
            configs_scanned += 1
            try:
                findings = _audit_mcp_config(
                    config_path,
                    repo_root=None,
                    trusted_domains=domains,
                )
                all_findings.extend(findings)
            except Exception as exc:
                errors.append(f"failed to audit {config_path}: {exc}")

    # --- Build report ---
    check_counts: dict[str, int] = {}
    for f in all_findings:
        cid = f["check_id"]
        check_counts[cid] = check_counts.get(cid, 0) + 1

    total_errors = sum(1 for f in all_findings if f["severity"] == "error")
    total_warnings = sum(1 for f in all_findings if f["severity"] == "warning")

    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {
            "dev_root": str(root),
            "repos_scanned": repos_scanned,
            "configs_scanned": configs_scanned,
            "user_configs_scanned": user_configs_scanned,
            "check_user_configs": check_user_configs,
            "max_depth": max_depth,
            "trusted_domains": domains,
            "exclude_repo_globs": globs,
        },
        "summary": {
            "total_findings": len(all_findings),
            "total_errors": total_errors,
            "total_warnings": total_warnings,
            "findings_by_check": sorted(check_counts.items(), key=lambda x: -x[1]),
        },
        "findings": all_findings[:500],
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
