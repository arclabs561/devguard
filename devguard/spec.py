"""Specification system for defining what to monitor."""

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class DiscoveryRule(BaseModel):
    """A rule for discovering resources to monitor."""

    name: str = Field(description="Name of the discovery rule")
    type: str = Field(description="Type of resource: npm, github, vercel, fly, domain, etc.")
    method: str = Field(description="Discovery method: cli, file_scan, api, custom")
    command: str | None = Field(None, description="CLI command to run (if method=cli)")
    command_parser: str | None = Field(
        None, description="How to parse command output: json, lines, regex"
    )
    file_pattern: str | None = Field(
        None, description="File pattern to search for (if method=file_scan)"
    )
    file_extractor: str | None = Field(
        None, description="How to extract data from files: json_path, regex, yaml_path"
    )
    extract_path: str | None = Field(
        None, description="Path to extract (e.g., JSON path, YAML path, regex pattern)"
    )
    timeout: int = Field(10, description="Timeout in seconds")
    enabled: bool = Field(True, description="Whether this rule is enabled")
    metadata: dict[str, Any] = Field(default_factory=dict)


class LocalDevSweepSpec(BaseModel):
    """Policy-based sweep over local dev repos (git working trees)."""

    enabled: bool = Field(True, description="Whether this sweep is enabled (on by default)")
    max_depth: int = Field(
        2,
        description="How deep under dev_root to look for git repos (bounded).",
    )
    max_blob_mb: int = Field(
        5, description="Flag tracked files larger than this many MiB (working tree size)."
    )
    output: str = Field(
        "devguard_sweep_dev.json", description="Where to write the JSON report (path)."
    )
    deny_globs: list[str] = Field(
        default_factory=list,
        description="Additional deny globs (appended to devguard defaults).",
    )


class LocalDirtyWorktreeSecretsSweepSpec(BaseModel):
    """Scan only *dirty* local git worktrees for secrets (redacted output).

    This targets:
    - untracked files
    - modified but uncommitted changes
    - local-only repos not pushed yet
    """

    enabled: bool = Field(False, description="Whether this sweep is enabled")
    dev_root: str | None = Field(
        None,
        description="Workspace root to discover git repos under (default: \ or current directory).",
    )
    max_depth: int = Field(
        2, description="How deep under dev_root to look for git repos (bounded)."
    )
    only_dirty: bool = Field(
        True, description="Only scan repos with uncommitted/untracked changes."
    )
    exclude_repo_globs: list[str] = Field(
        default_factory=lambda: [
            "*/_trash/*",
            "*/_scratch/*",
            "*/_external/*",
            "*/_archive/*",
            "*/_forks/*",
        ],
        description="Glob patterns (matched against repo paths) to exclude from scanning.",
    )
    max_paths_per_repo: int = Field(
        50,
        description="Maximum number of dirty file paths to scan per repo (bounds runtime).",
    )
    include_ignored_files: bool = Field(
        False,
        description="If true, also scan untracked files that are ignored by gitignore (noisy).",
    )
    check_upstream: bool = Field(
        True,
        description="If true, compute ahead/behind vs upstream (may be stale if you haven't fetched).",
    )
    fetch_remotes: bool = Field(
        False,
        description="If true, run a fast `git fetch` before ahead/behind (slower; network).",
    )
    max_concurrency: int = Field(4, description="Maximum concurrent repo scans.")
    timeout_s: int = Field(180, description="Per-repo timeout upper bound in seconds.")
    output: str = Field(
        ".state/devguard/local-dirty-worktree-secrets.json",
        description="Where to write the redacted JSON report (path).",
    )


class ProjectFlauditSweepSpec(BaseModel):
    """Files-to-prompt per project + OpenRouter/Gemini flaw analysis.

    For each project (or k most recently edited), aggregates README, impl, tests,
    and optional rules into a prompt, then uses OpenRouter + Gemini to find:
    readme/impl drift, readme/tests mismatch, rules violations.

    All paths and patterns are configurable; defaults suit a typical super-workspace
    but work for any layout.
    """

    enabled: bool = Field(False, description="Whether this sweep is enabled")
    dev_root: str | None = Field(
        None,
        description="Workspace root. Default: \ or current directory when unset.",
    )
    k_recent: int = Field(
        5,
        description="Number of most recently edited projects to analyze.",
    )
    max_depth: int = Field(2, description="How deep under dev_root to look for git repos.")
    model_id: str = Field(
        "google/gemini-2.5-flash",
        description="OpenRouter model ID (e.g. google/gemini-2.5-flash, google/gemini-3.1-pro-preview).",
    )
    include_rules: bool = Field(
        True,
        description="Include per-repo .cursor/rules in the prompt.",
    )
    workspace_rules_path: str | None = Field(
        None,
        description="Optional path to workspace-level rules (e.g. parent .cursor/rules). "
        "When set, rules from this dir are included for rules-violation checks. "
        "Use when repos live under a super-workspace with shared rules.",
    )
    workspace_rules_include: list[str] = Field(
        default_factory=list,
        description="Rule filenames to include from workspace_rules_path (e.g. user-core.mdc). "
        "If empty and workspace_rules_path is set, a default set is used.",
    )
    max_workspace_rules_chars: int = Field(
        15_000,
        description="Max chars for workspace rules in the prompt.",
    )
    severity_guidance: str | None = Field(
        None,
        description="Optional custom severity guidance for the LLM. If unset, a default calibration is used.",
    )
    exclude_repo_globs: list[str] = Field(
        default_factory=lambda: [
            "*/_trash/*",
            "*/_scratch/*",
            "*/_external/*",
            "*/_archive/*",
            "*/_forks/*",
        ],
        description="Glob patterns to exclude repos from analysis.",
    )
    depth_0_skip_prefixes: list[str] = Field(
        default_factory=lambda: ["_", "."],
        description="At depth 0, skip dirs whose names start with these. Use [] to disable.",
    )
    depth_0_allow_names: list[str] = Field(
        default_factory=lambda: ["_infra"],
        description="Depth-0 dir names to allow despite depth_0_skip_prefixes.",
    )
    max_prompt_chars: int = Field(
        120_000,
        description="Max prompt size before truncation.",
    )
    scope_recent_commits: int | None = Field(
        None,
        description="When set, only include files changed in last N commits (plus manifests + README). "
        "Reduces prompt size and focuses on recent changes. None = full repo.",
    )
    public_repo_names: list[str] = Field(
        default_factory=list,
        description="When non-empty, only analyze these repos (by directory name under dev_root). "
        "Used to focus on public crates; ignores k_recent and runs on all matching repos (up to cap).",
    )
    stricter_public_prompt: bool = Field(
        True,
        description="When public_repo_names is set, use a stricter system prompt aimed at public crate quality.",
    )
    output: str = Field(
        ".state/devguard/project-flaudit.json",
        description="Where to write the JSON report.",
    )


class SSHKeyAuditSweepSpec(BaseModel):
    """Audit SSH keys for weak algorithms, missing passphrases, and stale registrations."""

    enabled: bool = Field(True, description="Whether this sweep is enabled (on by default)")
    ssh_dir: str = Field(
        "~/.ssh",
        description="Path to SSH directory to scan.",
    )
    check_github: bool = Field(
        True,
        description="Cross-reference local keys with GitHub via `gh ssh-key list`.",
    )
    min_rsa_bits: int = Field(
        3072,
        description="Minimum RSA key size in bits; keys below this are flagged.",
    )
    flag_ecdsa: bool = Field(
        False,
        description="Flag ECDSA keys (some consider NIST curves weak).",
    )
    output: str = Field(
        ".state/devguard/ssh-key-audit.json",
        description="Where to write the JSON report.",
    )


class GitignoreAuditSweepSpec(BaseModel):
    """Audit .gitignore files across local repos for missing hygiene patterns.

    Checks for common patterns (.env, .state/, *.log, etc.) and flags repos --
    especially public ones -- that are missing them.
    """

    enabled: bool = Field(True, description="Whether this sweep is enabled (on by default)")
    dev_root: str | None = Field(
        None,
        description="Workspace root. Default: \ or current directory when unset.",
    )
    max_depth: int = Field(2, description="How deep under dev_root to look for git repos.")
    exclude_repo_globs: list[str] = Field(
        default_factory=lambda: [
            "*/_trash/*",
            "*/_scratch/*",
            "*/_external/*",
            "*/_archive/*",
            "*/_forks/*",
        ],
        description="Glob patterns to exclude repos from the audit.",
    )
    output: str = Field(
        ".state/devguard/gitignore-audit.json",
        description="Where to write the JSON report.",
    )


class DependencyAuditSweepSpec(BaseModel):
    """Audit dependencies across local repos for known vulnerabilities.

    Detects language by manifest/lock files and runs the appropriate audit tool
    (cargo-audit, npm audit, pip-audit). Produces a unified report with
    per-repo findings bucketed by severity.
    """

    enabled: bool = Field(True, description="Whether this sweep is enabled (on by default)")
    dev_root: str | None = Field(
        None,
        description="Workspace root. Default: \ or current directory when unset.",
    )
    max_depth: int = Field(2, description="How deep under dev_root to look for git repos.")
    exclude_repo_globs: list[str] = Field(
        default_factory=lambda: [
            "*/_trash/*",
            "*/_scratch/*",
            "*/_external/*",
            "*/_archive/*",
            "*/_forks/*",
        ],
        description="Glob patterns to exclude repos from the audit.",
    )
    max_concurrency: int = Field(4, description="Maximum concurrent repo scans.")
    timeout_s: int = Field(120, description="Per-repo timeout upper bound in seconds.")
    engines: list[str] = Field(
        default_factory=lambda: ["cargo-audit", "npm-audit", "pip-audit"],
        description="Audit engines to run. Supported: cargo-audit, npm-audit, pip-audit.",
    )
    output: str = Field(
        ".state/devguard/dependency-audit.json",
        description="Where to write the JSON report.",
    )


class PublicGitHubSecretsSweepSpec(BaseModel):
    """Spec for scanning public GitHub repos for leaked secrets (redacted output)."""

    enabled: bool = Field(True, description="Whether this sweep is enabled")

    owners: list[str] = Field(
        default_factory=list,
        description="GitHub owners (user/org) whose public repos should be scanned.",
    )
    max_repos: int = Field(200, description="Maximum number of repos to scan (bounded).")
    include_repos: list[str] = Field(
        default_factory=list,
        description="Optional glob patterns for repo full names to include (owner/name).",
    )
    exclude_repos: list[str] = Field(
        default_factory=list,
        description="Optional glob patterns for repo full names to exclude (owner/name).",
    )
    include_forks: bool = Field(False, description="Whether to include forks.")

    engines: list[str] = Field(
        default_factory=lambda: ["trufflehog"],
        description="Secret scanning engines to run. Supported: trufflehog, kingfisher",
    )

    timeout_s: int = Field(
        900,
        description="Per-repo timeout upper bound in seconds (bounded internally).",
    )
    max_concurrency: int = Field(
        4,
        description="Maximum concurrent repo scans (bounded parallelism for speed).",
    )
    fail_on_errors: bool = Field(
        False,
        description="If true, treat scan errors (missed repos) as a CI failure.",
    )

    output: str = Field(
        "public_github_secret_scan.json",
        description="Where to write the redacted JSON report (path).",
    )


class AIEditorConfigAuditSweepSpec(BaseModel):
    """Audit AI editor configs (Claude, Cursor, Copilot, MCP) across repos.

    Checks CLAUDE.md presence/validity, .claude/ structure, Cursor .mdc frontmatter,
    MCP JSON validity, hardcoded secrets, cross-tool rule consistency, and gitignore coverage.
    """

    enabled: bool = Field(True, description="Whether this sweep is enabled (on by default)")
    dev_root: str | None = Field(
        None,
        description="Workspace root. Default: \ or current directory when unset.",
    )
    max_depth: int = Field(2, description="How deep under dev_root to look for git repos.")
    exclude_repo_globs: list[str] = Field(
        default_factory=lambda: [
            "*/_trash/*",
            "*/_scratch/*",
            "*/_external/*",
            "*/_archive/*",
            "*/_forks/*",
        ],
        description="Glob patterns to exclude repos from the audit.",
    )
    only_with_configs: bool = Field(
        True,
        description="Only report repos that have at least one AI editor config.",
    )
    output: str = Field(
        ".state/devguard/ai-editor-config-audit.json",
        description="Where to write the JSON report.",
    )


class CargoPublishAuditSweepSpec(BaseModel):
    """Audit Rust repos for correct cargo publish CI pipelines.

    Checks the full e2e: tag triggers, OIDC trusted publishing, dry-run on PRs,
    version/tag consistency, workflow completeness, and token hygiene.
    """

    enabled: bool = Field(False, description="Whether this sweep is enabled")
    dev_root: str | None = Field(
        None,
        description="Workspace root. Default: \ or current directory when unset.",
    )
    max_depth: int = Field(2, description="How deep under dev_root to look for git repos.")
    exclude_repo_globs: list[str] = Field(
        default_factory=lambda: [
            "*/_trash/*",
            "*/_scratch/*",
            "*/_external/*",
            "*/_archive/*",
            "*/_forks/*",
        ],
        description="Glob patterns to exclude repos from the audit.",
    )
    only_public: bool = Field(
        False,
        description="Only audit repos that appear public (have a LICENSE file).",
    )
    repo_names: list[str] = Field(
        default_factory=list,
        description="When non-empty, only audit these repos (by directory name). "
        "Useful to focus on published crates.",
    )
    output: str = Field(
        ".state/devguard/cargo-publish-audit.json",
        description="Where to write the JSON report.",
    )


class PublishAuditSweepSpec(BaseModel):
    """Audit PyPI and npm repos for correct publish CI pipelines.

    Checks OIDC trusted publishing, workflow correctness, version consistency,
    license presence, and secret hygiene. Complements cargo_publish_audit for
    non-Rust ecosystems.
    """

    enabled: bool = Field(False, description="Whether this sweep is enabled")
    dev_root: str | None = Field(
        None,
        description="Workspace root. Default: \ or current directory when unset.",
    )
    max_depth: int = Field(2, description="How deep under dev_root to look for git repos.")
    exclude_repo_globs: list[str] = Field(
        default_factory=lambda: [
            "*/_trash/*",
            "*/_scratch/*",
            "*/_external/*",
            "*/_archive/*",
            "*/_forks/*",
        ],
        description="Glob patterns to exclude repos from the audit.",
    )
    ecosystems: list[str] = Field(
        default_factory=lambda: ["pypi", "npm"],
        description="Ecosystems to audit. Supported: pypi, npm.",
    )
    output: str = Field(
        ".state/devguard/publish-audit.json",
        description="Where to write the JSON report.",
    )


class PreCommitAuditSweepSpec(BaseModel):
    """Audit pre-commit hook configs across local repos for secret scanning coverage."""

    enabled: bool = Field(False, description="Whether this sweep is enabled")
    dev_root: str | None = Field(
        None,
        description="Workspace root. Default: \ or current directory when unset.",
    )
    max_depth: int = Field(2, description="How deep under dev_root to look for git repos.")
    exclude_repo_globs: list[str] = Field(
        default_factory=lambda: [
            "*/_trash/*",
            "*/_scratch/*",
            "*/_external/*",
            "*/_archive/*",
            "*/_forks/*",
        ],
        description="Glob patterns to exclude repos from the audit.",
    )
    required_hooks: list[str] = Field(
        default_factory=lambda: ["detect-secrets", "gitleaks", "trufflehog"],
        description="Secret scanning hook IDs; at least one must be present per repo.",
    )
    output: str = Field(
        ".state/devguard/pre-commit-audit.json",
        description="Where to write the JSON report.",
    )


class CredentialFileAuditSweepSpec(BaseModel):
    """Audit credential files for permission issues and plaintext secrets.

    Machine-scoped sweep checking well-known dotfiles (~/.aws/credentials,
    ~/.npmrc, ~/.netrc, ~/.docker/config.json, ~/.kube/config, ~/.pypirc, ~/.ssh/).
    """

    enabled: bool = Field(True, description="Whether this sweep is enabled (on by default)")
    home_dir: str | None = Field(
        None,
        description="Home directory to scan. Default: $HOME.",
    )
    extra_paths: list[str] = Field(
        default_factory=list,
        description="Additional credential file paths to check.",
    )
    skip_missing: bool = Field(
        True,
        description="Skip files/dirs that don't exist instead of reporting errors.",
    )
    output: str = Field(
        ".state/devguard/credential-file-audit.json",
        description="Where to write the JSON report.",
    )


class MCPSecurityAuditSweepSpec(BaseModel):
    """Deep MCP config security scanning.

    Checks hardcoded secrets, command injection, untrusted URLs, lethal trifecta
    servers, env literal hygiene, and git-tracking of secret-bearing configs.
    """

    enabled: bool = Field(True, description="Whether this sweep is enabled")
    dev_root: str | None = Field(
        None,
        description="Workspace root. Default: \ or current directory when unset.",
    )
    max_depth: int = Field(2, description="How deep under dev_root to look for git repos.")
    exclude_repo_globs: list[str] = Field(
        default_factory=lambda: [
            "*/_trash/*",
            "*/_scratch/*",
            "*/_external/*",
            "*/_archive/*",
            "*/_forks/*",
        ],
        description="Glob patterns to exclude repos from scanning.",
    )
    check_user_configs: bool = Field(
        True,
        description="Also scan user-level MCP configs (~/.claude/, ~/.cursor/, Claude desktop).",
    )
    trusted_domains: list[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1"],
        description="Domains considered trusted for MCP server URLs.",
    )
    output: str = Field(
        ".state/devguard/mcp-security-audit.json",
        description="Where to write the JSON report.",
    )


class SweepSpec(BaseModel):
    """Spec for all sweeps (policy checks)."""

    local_dev: LocalDevSweepSpec = Field(
        default_factory=lambda: LocalDevSweepSpec(),
        description="Local dev workspace sweep",
    )
    public_github_secrets: PublicGitHubSecretsSweepSpec = Field(
        default_factory=lambda: PublicGitHubSecretsSweepSpec(),
        description="Scan public GitHub repos for leaked secrets (redacted)",
    )
    local_dirty_worktree_secrets: LocalDirtyWorktreeSecretsSweepSpec = Field(
        default_factory=lambda: LocalDirtyWorktreeSecretsSweepSpec(),
        description="Scan dirty local git worktrees for secrets (redacted)",
    )
    project_flaudit: ProjectFlauditSweepSpec = Field(
        default_factory=lambda: ProjectFlauditSweepSpec(),
        description="Files-to-prompt + OpenRouter/Gemini flaw analysis per project",
    )
    gitignore_audit: GitignoreAuditSweepSpec = Field(
        default_factory=lambda: GitignoreAuditSweepSpec(),
        description="Audit .gitignore files for missing hygiene patterns",
    )
    dependency_audit: DependencyAuditSweepSpec = Field(
        default_factory=lambda: DependencyAuditSweepSpec(),
        description="Audit dependencies for known vulnerabilities",
    )
    ssh_key_audit: SSHKeyAuditSweepSpec = Field(
        default_factory=lambda: SSHKeyAuditSweepSpec(),
        description="Audit SSH keys for weak algorithms, missing passphrases, stale registrations",
    )
    cargo_publish_audit: CargoPublishAuditSweepSpec = Field(
        default_factory=lambda: CargoPublishAuditSweepSpec(),
        description="Audit Rust repos for correct cargo publish CI pipelines",
    )
    ai_editor_config_audit: AIEditorConfigAuditSweepSpec = Field(
        default_factory=lambda: AIEditorConfigAuditSweepSpec(),
        description="Audit AI editor configs (Claude, Cursor, Copilot, MCP) across repos",
    )
    publish_audit: PublishAuditSweepSpec = Field(
        default_factory=lambda: PublishAuditSweepSpec(),
        description="Audit PyPI and npm repos for correct publish CI pipelines",
    )
    pre_commit_audit: PreCommitAuditSweepSpec = Field(
        default_factory=lambda: PreCommitAuditSweepSpec(),
        description="Audit pre-commit configs for secret scanning hooks",
    )
    credential_file_audit: CredentialFileAuditSweepSpec = Field(
        default_factory=lambda: CredentialFileAuditSweepSpec(),
        description="Audit credential files for permission issues and plaintext secrets",
    )
    mcp_security_audit: MCPSecurityAuditSweepSpec = Field(
        default_factory=lambda: MCPSecurityAuditSweepSpec(),
        description="Deep MCP config security scanning (secrets, injection, trifecta)",
    )


class MonitorSpec(BaseModel):
    """Specification of what to monitor."""

    name: str = Field(description="Name of this monitoring spec")
    description: str | None = Field(None, description="Description of what this monitors")
    discovery_rules: list[DiscoveryRule] = Field(
        default_factory=list, description="Rules for auto-discovery"
    )
    manual_resources: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Manually specified resources: {type: [names]}",
    )
    filters: dict[str, Any] = Field(
        default_factory=dict,
        description="Filters to apply to discovered resources",
    )
    sweeps: SweepSpec = Field(
        default_factory=SweepSpec,
        description="Policy sweeps (e.g., local dev repo hygiene).",
    )


def load_spec(spec_path: Path) -> MonitorSpec:
    """Load a monitoring spec from a file."""
    import yaml  # type: ignore[import-not-found]

    with open(spec_path) as f:
        data = yaml.safe_load(f) or {}

    # Be tolerant of YAML keys that are present but null (common when a section is
    # left empty with only comments).
    if data.get("discovery_rules") is None:
        data["discovery_rules"] = []
    if data.get("manual_resources") is None:
        data["manual_resources"] = {}
    if data.get("filters") is None:
        data["filters"] = {}
    if data.get("sweeps") is None:
        data["sweeps"] = {}
    return MonitorSpec(**data)


def get_default_spec() -> MonitorSpec:
    """Get the default monitoring spec."""
    return MonitorSpec(
        name="default",
        description="Default devguard monitoring spec",
        discovery_rules=[
            DiscoveryRule(  # type: ignore[call-arg]
                name="npm_list",
                type="npm",
                method="cli",
                command="npm list --depth=0 --json",
                command_parser="json",
                extract_path="dependencies.keys()",
                timeout=10,
            ),
            DiscoveryRule(  # type: ignore[call-arg]
                name="npm_package_json",
                type="npm",
                method="file_scan",
                file_pattern="**/package.json",
                file_extractor="json_path",
                extract_path="name",
                timeout=30,
            ),
            DiscoveryRule(  # type: ignore[call-arg]
                name="github_repos",
                type="github",
                method="cli",
                command="gh repo list --json nameWithOwner --limit 100",
                command_parser="json",
                extract_path="[].nameWithOwner",
                timeout=10,
            ),
            DiscoveryRule(  # type: ignore[call-arg]
                name="fly_apps",
                type="fly",
                method="cli",
                command="flyctl apps list --json",
                command_parser="json",
                extract_path="[].Name",
                timeout=10,
            ),
            DiscoveryRule(  # type: ignore[call-arg]
                name="vercel_projects",
                type="vercel",
                method="file_scan",
                file_pattern="**/vercel.json",
                file_extractor="json_path",
                extract_path="name",
                timeout=30,
            ),
            DiscoveryRule(  # type: ignore[call-arg]
                name="domains",
                type="domain",
                method="file_scan",
                file_pattern="**/*.{json,yaml,yml,toml,env}",
                file_extractor="regex",
                extract_path=r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
                timeout=30,
            ),
            DiscoveryRule(  # type: ignore[call-arg]
                name="github_commits",
                type="github_commits",
                method="cli",
                command="gh api user/events --jq '.[] | select(.type == \"PushEvent\") | {repo: .repo.name, message: .payload.commits[0].message, date: .created_at}' --limit 20",
                command_parser="json_lines",
                timeout=10,
            ),
            DiscoveryRule(  # type: ignore[call-arg]
                name="github_mentions",
                type="github_mentions",
                method="cli",
                command="gh api search/issues -f 'q=mentions:{username}' --jq '.items[] | {title: .title, url: .html_url, state: .state, created_at: .created_at}' --limit 20",
                command_parser="json_lines",
                timeout=10,
            ),
            DiscoveryRule(  # type: ignore[call-arg]
                name="ssh_keys",
                type="ssh_key",
                method="file_scan",
                file_pattern="~/.ssh/*.pub",
                file_extractor="raw",
                timeout=5,
            ),
            DiscoveryRule(  # type: ignore[call-arg]
                name="github_username",
                type="username",
                method="cli",
                command="gh api user --jq .login",
                command_parser="text",
                timeout=5,
            ),
        ],
    )
