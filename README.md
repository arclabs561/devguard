# devguard

devguard scans your developer workspace for security and hygiene issues. It runs a set of sweeps -- automated checks across local repos, SSH keys, dependencies, and more -- and reports findings in one pass.

```
$ devguard sweep
local_dev:                    142 repos scanned, 0 findings
public_github_secrets:        18 repos scanned, 0 findings
local_dirty_worktree_secrets: 47 repos scanned, 0 findings
gitignore_audit:              3 repos with gaps (1 public)
dependency_audit:             12 vulns across 5 repos (2 critical)
ssh_key_audit:                1 weak key, 2 stale GitHub keys
ai_editor_config_audit:       47 repos checked, 2 errors
```

## Quick start

Requires Python >= 3.11.

```bash
pip install devguard
devguard doctor                # check prerequisites (trufflehog, cargo-audit, etc.)
devguard sweep                 # run all enabled sweeps
```

No spec file is required. Without one, devguard uses built-in defaults. Create `devguard.spec.yaml` to customize which sweeps run and their parameters.

## Sweeps

### Security

| Sweep | Description |
|-------|-------------|
| `public_github_secrets` | Scan public GitHub repos for committed secrets (TruffleHog). |
| `dependency_audit` | Check repos for known vulnerabilities in dependencies (npm audit, pip-audit, cargo-audit). |
| `ssh_key_audit` | Audit local SSH keys for weak algorithms, short key lengths, and stale GitHub deploy keys. |
| `local_dirty_worktree_secrets` | Scan uncommitted changes in local repos for secrets before they reach a commit. |

### Hygiene

| Sweep | Description |
|-------|-------------|
| `gitignore_audit` | Find repos missing `.gitignore` or lacking expected ignore patterns for their language. |
| `ai_editor_config_audit` | Check AI editor configs (Cursor rules, Claude settings) for consistency across repos. |
| `cargo_publish_audit` | Verify Rust crates have publish CI, correct metadata, and no publish blockers. |
| `publish_audit` | Audit PyPI and npm repos for correct CI publish pipelines, OIDC trusted publishing, and version/license consistency. |

### Analysis

| Sweep | Description |
|-------|-------------|
| `project_flaudit` | LLM-driven audit (OpenRouter/Gemini): README drift, test gaps, rule violations. |

### Workspace

| Sweep | Description |
|-------|-------------|
| `local_dev` | Scan local repos for accidentally committed large files, binaries, and dev artifacts. |

## Configuration

Copy `devguard.spec.example.yaml` to `devguard.spec.yaml` and edit to taste. The spec file controls which sweeps are enabled, their parameters, and output paths.

Most sweeps work with zero configuration. Sweeps that need external access:

- `public_github_secrets`: requires `GITHUB_TOKEN` (for GitHub API).
- `project_flaudit`: requires `OPENROUTER_API_KEY`.
- `ssh_key_audit` with `check_github: true`: requires `GITHUB_TOKEN`.
- `dependency_audit`: requires audit tools installed (`npm`, `pip-audit`, `cargo-audit`).

Environment variables can be set in `.env` or exported in your shell.

## Pre-commit hooks

devguard ships `.pre-commit-hooks.yaml` with three hooks: `devguard-gitignore`, `devguard-ai-config`, and `devguard-secrets`. Add to your `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/arclabs561/devguard
  rev: main
  hooks:
    - id: devguard-gitignore
    - id: devguard-secrets
```

## Library usage

Sweep modules can be imported directly for scripting or integration:

```python
from devguard.sweeps.ssh_key_audit import audit_ssh_keys
from devguard.sweeps.dependency_audit import audit_dependencies
```

## Development

```bash
pip install -e ".[dev]"       # editable install for development
pytest
ruff check .
mypy devguard/
```

## License

MIT

<details>
<summary>Legacy: Service monitoring (npm, Vercel, Fly.io, GitHub)</summary>

devguard originally provided unified monitoring for npm packages, GitHub repositories, and Fly.io/Vercel deployments. This functionality still exists but is secondary to the sweep system.

### Monitored services

- **npm packages** for security vulnerabilities
- **GitHub repositories** for Dependabot security alerts
- **Fly.io deployments** for health status
- **Vercel deployments** for deployment status
- **Container/Dockerfile** security best practices
- **Secret scanning** (TruffleHog or regex fallback)
- **AWS IAM** security posture for satellite nodes
- **AWS Cost** monitoring with budget alerts
- **API usage/credits** for LLM providers (OpenRouter, Anthropic, OpenAI, Perplexity, Groq)
- **Firecrawl API** credit usage
- **Tavily API** usage tracking
- **Tailscale** mesh network health
- **Domain/SSL** certificate expiry
- **Docker Swarm** cluster health
- **Red team security testing** for deployment endpoints
- **Web dashboard** for real-time monitoring
- **MCP server** for AI agent integration

### Legacy commands

```bash
devguard check           # run monitoring checks
devguard check --watch   # continuous monitoring
devguard mcp             # start MCP server
devguard dashboard       # start web dashboard
devguard discover        # auto-discover resources to monitor
devguard config          # show current configuration
devguard auth gh         # authenticate with GitHub
devguard auth-status     # show auth status for all services
```

### Legacy configuration

Set environment variables in `.env`:

```bash
GITHUB_TOKEN=your_github_token
VERCEL_TOKEN=your_vercel_token
FLY_API_TOKEN=your_fly_token
SNYK_TOKEN=your_snyk_token
GITHUB_ORG=your_org_name
NPM_PACKAGES_TO_MONITOR=package1,package2
GITHUB_REPOS_TO_MONITOR=owner/repo1,owner/repo2
FLY_APPS_TO_MONITOR=app1,app2
VERCEL_PROJECTS_TO_MONITOR=project1,project2
DASHBOARD_ENABLED=false
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=8080
DASHBOARD_API_KEY=your_secure_key
```

### Architecture (legacy)

- **devguard**: Main orchestrator managing checkers and reports
- **BaseChecker**: Abstract base class for all checkers
- **Reporter**: Output formatting, webhooks, email delivery
- **Checkers**: NpmChecker, GitHubChecker, VercelChecker, FlyChecker, ContainerChecker, SecretChecker, AWSIAMChecker, RedTeamChecker

</details>
