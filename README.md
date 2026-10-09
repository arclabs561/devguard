# devguard

Developer workspace security scanner.

`devguard` runs local sweeps across repos, dependency manifests, SSH keys,
credential files, and AI editor configs. It reports findings as text, JSON, or
SARIF.

```text
$ devguard sweep
local_dev:                    142 repos scanned, 0 findings
public_github_secrets:        18 repos scanned, 0 findings
local_dirty_worktree_secrets: 47 repos scanned, 0 findings
gitignore_audit:              3 repos with gaps
dependency_audit:             12 vulns across 5 repos
ssh_key_audit:                1 weak key, 2 stale GitHub keys
ai_editor_config_audit:       47 repos checked, 2 errors
```

## Install

Requires Python 3.11 or newer.

```bash
pip install devguard
```

For local development:

```bash
pip install -e ".[dev]"
```

## Usage

Check external tools:

```bash
devguard doctor
```

Run all enabled sweeps:

```bash
devguard sweep
```

Run one sweep (named sweeps run even when the spec leaves them disabled):

```bash
devguard sweep --only dependency_audit
```

Scan one repo:

```bash
devguard sweep --repo /path/to/repo
devguard sweep --repo https://github.com/owner/repo --format json
```

## Configuration

No spec file is required. Without one, `devguard` uses built-in defaults.

Create `devguard.spec.yaml` when you need to enable or tune sweeps:

```bash
cp devguard.spec.example.yaml devguard.spec.yaml
```

Environment variables can be set in `.env` or exported in the shell.

Secret checking scans the current Git repository by default. Set
`SECRET_SCAN_PATHS` to comma-separated repository or workspace paths for a wider scan.

Sweeps that need external access:

| Sweep | Requirement |
| --- | --- |
| `public_github_secrets` | `GITHUB_TOKEN` and TruffleHog |
| `ssh_key_audit` with `check_github: true` | `GITHUB_TOKEN` |
| `dependency_audit` | `npm`, `pip-audit`, or `cargo-audit`, depending on repo type |
| `project_flaudit` | `OPENROUTER_API_KEY` |

## Sweeps

| Sweep | Checks |
| --- | --- |
| `local_dev` | Large files, binaries, and dev artifacts in local repos |
| `public_github_secrets` | Committed secrets in public GitHub repos |
| `local_dirty_worktree_secrets` | Secrets in uncommitted local changes |
| `local_history_secrets` | Secrets anywhere in local git history, including deleted files (gitleaks, TruffleHog, or built-in regex) |
| `exec_config_audit` | Repo configs that run commands on open: Claude Code hooks, VS Code folderOpen tasks, devcontainer commands, `.envrc` |
| `credential_file_audit` | Plaintext secrets and permissions in common credential files |
| `mcp_security_audit` | Hardcoded secrets and risky MCP command configuration |
| `dependency_audit` | Known vulnerable dependencies |
| `ssh_key_audit` | Weak, short, or stale SSH keys |
| `gitignore_audit` | Missing `.gitignore` files and missing language ignore patterns |
| `repo_hygiene` | Public-text leak patterns and repo hygiene checks |
| `git_identity_audit` | Git author email policy in config, env, and optional history |
| `ai_editor_config_audit` | Cursor and Claude config consistency |
| `cargo_publish_audit` | Rust crate publish metadata and CI blockers |
| `publish_audit` | PyPI and npm publish metadata and trusted-publishing setup |
| `pre_commit_audit` | Missing or incomplete secret-scanning pre-commit hooks |
| `project_flaudit` | LLM-assisted repo audit |
| `repo_lint` | Rust workspace hygiene: own-crate pin drift, README version lines, Cargo metadata, CI gaps (off by default, never changes the exit code) |

## Pre-commit Hooks

`devguard` ships `.pre-commit-hooks.yaml`:

```yaml
- repo: https://github.com/arclabs561/devguard
  rev: main
  hooks:
    - id: devguard-gitignore
    - id: devguard-secrets
```

Python dependency auditing requires a fully pinned `requirements.txt` export. It
uses `pip-audit --no-deps --disable-pip --strict -r requirements.txt`, auditing
only declared inputs without invoking pip or inspecting the host environment.
Include transitive dependencies in the export when that coverage is needed;
Devguard does not infer completeness. Repositories with only `uv.lock` or
`poetry.lock` report an unsupported-input error. Tool failures, invalid output,
and skipped dependencies produce audit errors (CLI exit 2); missing tools remain
reported as skipped.

## Library Usage

Sweep modules can be imported directly:

```python
from devguard.sweeps.dependency_audit import audit_dependencies
from devguard.sweeps.ssh_key_audit import audit_ssh_keys
```

## Legacy Monitoring

The older service-monitoring commands (`check`, `dashboard`, `mcp`, and related
checkers) are still present but are not the primary workflow. See
[`docs/legacy-monitoring.md`](docs/legacy-monitoring.md).

## Development

```bash
pytest
ruff check .
mypy devguard/
```

## License

MIT OR Apache-2.0
