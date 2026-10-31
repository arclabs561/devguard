# devguard

Developer workspace security scanner.

`devguard` runs local sweeps across repos, dependency manifests, SSH keys,
credential files, and AI editor configs. It reports findings as text, JSON, or
SARIF.

```text
$ devguard sweep --repo . --only local_dev --only gitignore_audit
local_dev report: ~/.local/state/devguard/local-dev-sweep.json
Repos scanned: 1
Findings: 0
gitignore_audit report: ~/.local/state/devguard/gitignore-audit.json
Repos scanned: 1
Repos without .gitignore: 0
Public repos with gaps: 1
Total gaps: 1
```

Each sweep with findings also prints a table of them.

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

# Audit one nested package; repeat --package-root for another
devguard sweep --repo /path/to/repo --only dependency_audit --package-root services/api --format json
```

`--package-root` requires a local `--repo` and exactly
`--only dependency_audit`, and paths must stay inside the repository. npm
requires `package-lock.json`, Cargo requires `Cargo.lock`, and Python requires
a fully pinned `requirements.txt` (audited with
`pip-audit --no-deps --disable-pip --strict`, so include transitive
dependencies in the export if you need them covered). Repositories with only
`uv.lock` or `poetry.lock` report an unsupported-input error. Audit tools may
contact their advisory services; this mode never installs or fixes packages.
The JSON report records the resolved scope, engine coverage, and SHA-256 input
hashes before and after the audit; changed inputs or incomplete engine coverage
produce an unknown result. Tool failures and invalid output exit 2; missing
tools are reported as skipped.

## Configuration

No spec file is required. Without one, `devguard` uses built-in defaults.

Create `devguard.spec.yaml` when you need to enable or tune sweeps:

```bash
cp devguard.spec.example.yaml devguard.spec.yaml
```

Without `--spec`, devguard uses the first of `./devguard.spec.yaml`,
`$DEVGUARD_SPEC`, and `~/.config/devguard/devguard.spec.yaml` (honoring
`XDG_CONFIG_HOME`), so personal settings can live outside any repository.

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
| `docs_quality` | Vale and readcost, or a wrapper with the same `--json` output |
| `public_text_leak` | `gh` (repo visibility; PR and issue text when enabled) |

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
| `repo_hygiene` | Public-text leak patterns plus structural hygiene: scattered doc dirs, committed generated data, hardcoded absolute paths in shell scripts, large blobs and build artifacts in history, declaration-only `[workspace.dependencies]` keys, path deps outside the repo, files referenced by build scripts and manifests that git does not track, crate-level `#![cfg(all(...))]` test gates, bare `#[ignore]` with no reason, a `cargo --features` argument naming a feature no manifest defines, test/example targets that use a feature-gated module without a gate or `required-features`, README install pins that disagree with the manifest version, stale `.gitkeep`, tracked editor/cache dirs, internal docs in public repos, tracked-but-ignored files, stray backups and OS junk. See `devguard/sweeps/repo_hygiene.py` for the full list |
| `git_identity_audit` | Git author emails in config, env, and history: forbidden domains, an `allowed_emails` list, or, with no policy, likely employer addresses under your own name |
| `ai_editor_config_audit` | Cursor and Claude config consistency |
| `cargo_publish_audit` | Rust crate publish metadata and CI blockers |
| `publish_audit` | PyPI and npm publish metadata and trusted-publishing setup |
| `pre_commit_audit` | Missing or incomplete secret-scanning pre-commit hooks |
| `project_flaudit` | LLM-assisted repo audit |
| `docs_quality` | Vale and readcost findings in README and `docs/` Markdown (advisory; missing tools or timeouts exit 3) |
| `public_text_leak` | Coordination vocabulary and configured private names in recent public commit messages, PR bodies, and comments |
| `publish_workflow_audit` | Publish/release workflows: tag push without credentials, MSRV pins missing from publish, semver checks over platform-only features, unpinned action refs |
| `repo_lint` | Rust workspace hygiene: own-crate pin drift, README version lines, Cargo metadata, CI gaps (off by default, never changes the exit code) |

The missing-pattern check in `gitignore_audit` is a pattern-presence heuristic.
It combines global and repository ignore patterns without evaluating Git’s rule
ordering or negation semantics. Zero gaps does not establish that files are
effectively excluded; a later negation can re-include an otherwise matched path.

`sweep-dev` and `local_dev` mark hits in forks as upstream-owned: a repo whose
`upstream` remote has a different owner than `origin`, or, when
`sweeps.local_dev.owners` (or `sweep-dev --owner`, repeatable) is set, whose `origin`
belongs to another owner. Those hits stay in the report but do not change the
exit code; pass `--include-upstream` to count them.

Private names for `public_text_leak` (private repo names, internal hostnames)
belong in your untracked `devguard.spec.yaml`, not in this repository.

### Silencing a finding at its source

A finding can be excused where it is written, but only with a stated reason:

```text
# devguard: allow feature_name_unknown reason: historical log, commands kept verbatim
<!-- devguard: allow-file readme_install_version reason: README documents the next release -->
```

`allow` covers the lines that follow it (six), so a note above one stale command
excuses that command and not the rest of the file; `allow-file` covers the whole
file, for a document that is historical end to end. Both require `reason:` — an
annotation without one is ignored, so removing the reason re-exposes the finding
instead of hiding it behind a bare pragma.

## Pre-commit Hooks

`devguard` ships `.pre-commit-hooks.yaml`:

```yaml
- repo: https://github.com/arclabs561/devguard
  rev: main
  hooks:
    - id: devguard-gitignore
    - id: devguard-secrets
```

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
