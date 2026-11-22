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

Check the default-branch commit across all repositories owned by the signed-in
GitHub user, including accessible private repositories, forks, and archives:

```bash
devguard github-ci
devguard github-ci --json --fail-on-red
```

This command uses an authenticated `gh` CLI and reads GitHub's combined check
and commit-status result. It paginates through the full visible inventory.
`NO_REPORTED_CHECKS` means GitHub returned no checks for that particular
commit. Pull-request-only tests may have run on another commit. `EMPTY` marks
an empty repository. The JSON includes the branch, commit SHA and link.
By default this is a report. With `--fail-on-red`, a reported failure or error
exits 1. An incomplete API request exits 2.

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

A GitHub URL is cloned once into the devguard cache and refreshed with a
shallow fetch on later runs. `--no-cache` clones into a temporary directory
instead.

Scan many repos:

```bash
# Every repository of the signed-in GitHub user (needs an authenticated gh)
devguard fleet --mine

# Named repositories, an org, a list in a file, or local checkouts
devguard fleet owner/one owner/two https://github.com/owner/three
devguard fleet --owner some-org --pushed-since 2026-01-01 --exclude 'archive-*'
devguard fleet --repos-file repos.txt --jobs 8 --output fleet.json
devguard fleet --root ~/code
```

Preview a selection before scanning it. This example works offline with explicit
GitHub names. Dry runs list repositories without cloning them.

```bash
devguard fleet arclabs561/logp arclabs561/clump --match 'cl*' --dry-run --format json
```

```json
[
  {"name": "arclabs561/clump", "path": null, "visibility": null, "pushed_at": null}
]
```

With an authenticated GitHub CLI, save the public repositories you intend to
scan. The count goes to stderr. An empty selection writes `[]`.

```bash
devguard fleet --mine --visibility public --dry-run --format json > inventory.json
jq -r '.[].name' inventory.json > repos.txt
# Inspect repos.txt, then run a hygiene scan on those repositories.
devguard fleet --repos-file repos.txt --only repo_hygiene --output report.json
```

A local checkout has an absolute `path`. GitHub discovery supplies visibility
and the full push timestamp. Explicit targets can have unknown metadata, as
above. The default dry-run format is tab-separated text.

```text
$ devguard fleet --repos-file repos.txt --min-severity high --details none
Repositories (owner)
repo      ┃ crit ┃ high ┃ medi ┃ low ┃ info ┃ state  ┃ worst finding
deformat  │    · │    8 │    4 │  10 │    4 │ cached │ cargo_publish_audit/ungated_feature_test
readcost  │    · │    1 │    3 │   1 │    8 │ cached │ publish_audit/no_license_file
94 repositories with nothing at high or worse not listed (--min-severity info lists all).

96 repositories: 0 scanned, 96 from cache, 0 failed, 0 clean. 68 high, 218 medium, 543 low, 370 info. 16.8s.
```

`fleet` runs the repo-scoped sweeps (override with `--only`) on up to `--jobs`
repositories at once. Each repository is scanned by its own `devguard sweep`
process, so a crash or timeout in one is reported for that repository and the
rest still finish.

`docs_quality` is not in that default set, because it reports a repository as
not fully scanned unless both Vale and readcost are installed and Vale has
styles configured for it. To check READMEs across repositories, ask for it by
name: `devguard fleet --mine --only docs_quality`.

Two caches live under `$DEVGUARD_CACHE_DIR`, else `$XDG_CACHE_HOME/devguard`,
else `~/.cache/devguard`:

- Clones. A repository is cloned once (shallow) and updated with one fetch per
  run. `--offline` skips the fetch. `--full-history` clones every commit, which
  `local_history_secrets` needs to see anything beyond the head commit.
- Results. A result is reused while the head commit, the devguard version, the
  sweep selection, the spec file and the set of installed scanners are all
  unchanged. Local checkouts with staged changes, modified tracked files, or
  any untracked paths (including ignored files and empty directories) are
  rescanned because sweeps can inspect them. Selections that include the dependency
  audit always rescan because advisory data changes independently of the repository.
  `--no-cache` ignores and does not write results.

`devguard cache info` shows the size of both; `devguard cache clear` removes
them (`--results` keeps the clones).

The tables leave out repositories and checks with nothing at `--min-severity`
(default `low`) or worse; the totals count everything. `--details` (default
`high`) lists individual findings. `--format json` prints one document with
per-repository findings, counts and errors; `--full-reports` adds each sweep's
raw report. Exit codes: 0, 2 when a finding is at `--fail-on` (default `high`)
or worse, 3 when some repository was not fully scanned.

Before dependency checks were included by default, on one cold run over 96 repositories (2 cores, `--jobs 6`) the sweep took 134
seconds; the next run, with every clone fetched and no changes, took 17
seconds, and 1 second with `--offline`.

`--package-root` requires a local `--repo` and exactly
`--only dependency_audit`, and paths must stay inside the repository. npm
requires `package-lock.json`, Cargo requires `Cargo.lock`, and Python requires
a fully pinned `requirements.txt` (audited with
`pip-audit --no-deps --disable-pip --strict`, so include transitive
dependencies in the export if you need them covered). OSV-Scanner v2 handles uv, Poetry, Yarn, pnpm and Go files.
The default fleet selection includes dependency audits. Discovery checks nested
package directories, excluding build, vendor and virtual environment directories.
An unresolved manifest or unavailable tool is reported as incomplete (exit 3).
A checkout scan covers the lockfiles present on disk. A published library or
its consumer can have a different lockfile. For a public crate, run
`devguard audit-crate NAME VERSION` to audit the lockfile in that exact release.
The command verifies the archive against the crates.io index, reports the archive
and lockfile hashes, and runs OSV-Scanner on the packaged lockfile. Audit tools may contact their
advisory services. Fleet uses local OSV databases for private repositories
and repositories with unknown visibility, including local paths. Populate the
OSV-Scanner offline database cache first. Use `--online-dependencies` to allow
queries for those packages. `fleet --offline` keeps Git and dependency checks
offline. A missing database makes coverage incomplete.
Explicit package roots record SHA-256 input hashes before and after the audit.

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
| `dependency_audit` | `npm`, `pip-audit`, `cargo-audit`, or `osv-scanner` v2, depending on the lockfile |
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
