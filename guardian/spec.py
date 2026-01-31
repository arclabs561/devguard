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

    enabled: bool = Field(True, description="Whether this sweep is enabled")
    max_depth: int = Field(
        2,
        description="How deep under dev_root to look for git repos (bounded).",
    )
    max_blob_mb: int = Field(
        5, description="Flag tracked files larger than this many MiB (working tree size)."
    )
    output: str = Field(
        "guardian_sweep_dev.json", description="Where to write the JSON report (path)."
    )
    deny_globs: list[str] = Field(
        default_factory=list,
        description="Additional deny globs (appended to Guardian defaults).",
    )


class SweepSpec(BaseModel):
    """Spec for all sweeps (policy checks)."""

    local_dev: LocalDevSweepSpec = Field(
        default_factory=LocalDevSweepSpec, description="Local dev workspace sweep"
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
    import yaml

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
        description="Default Guardian monitoring spec",
        discovery_rules=[
            DiscoveryRule(
                name="npm_list",
                type="npm",
                method="cli",
                command="npm list --depth=0 --json",
                command_parser="json",
                extract_path="dependencies.keys()",
                timeout=10,
            ),
            DiscoveryRule(
                name="npm_package_json",
                type="npm",
                method="file_scan",
                file_pattern="**/package.json",
                file_extractor="json_path",
                extract_path="name",
                timeout=30,
            ),
            DiscoveryRule(
                name="github_repos",
                type="github",
                method="cli",
                command="gh repo list --json nameWithOwner --limit 100",
                command_parser="json",
                extract_path="[].nameWithOwner",
                timeout=10,
            ),
            DiscoveryRule(
                name="fly_apps",
                type="fly",
                method="cli",
                command="flyctl apps list --json",
                command_parser="json",
                extract_path="[].Name",
                timeout=10,
            ),
            DiscoveryRule(
                name="vercel_projects",
                type="vercel",
                method="file_scan",
                file_pattern="**/vercel.json",
                file_extractor="json_path",
                extract_path="name",
                timeout=30,
            ),
            DiscoveryRule(
                name="domains",
                type="domain",
                method="file_scan",
                file_pattern="**/*.{json,yaml,yml,toml,env}",
                file_extractor="regex",
                extract_path=r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
                timeout=30,
            ),
            DiscoveryRule(
                name="github_commits",
                type="github_commits",
                method="cli",
                command="gh api user/events --jq '.[] | select(.type == \"PushEvent\") | {repo: .repo.name, message: .payload.commits[0].message, date: .created_at}' --limit 20",
                command_parser="json_lines",
                timeout=10,
            ),
            DiscoveryRule(
                name="github_mentions",
                type="github_mentions",
                method="cli",
                command="gh api search/issues -f 'q=mentions:{username}' --jq '.items[] | {title: .title, url: .html_url, state: .state, created_at: .created_at}' --limit 20",
                command_parser="json_lines",
                timeout=10,
            ),
            DiscoveryRule(
                name="ssh_keys",
                type="ssh_key",
                method="file_scan",
                file_pattern="~/.ssh/*.pub",
                file_extractor="raw",
                timeout=5,
            ),
            DiscoveryRule(
                name="github_username",
                type="username",
                method="cli",
                command="gh api user --jq .login",
                command_parser="text",
                timeout=5,
            ),
        ],
    )
