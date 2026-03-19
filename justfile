default:
    @just --list

# Run security checks (~$0.01, ~30s)
check *args:
    @uv run python -m guardian check {{args}}

# Run checks in watch mode (FREE, continuous)
watch interval="3600":
    @uv run python -m guardian check --watch --interval {{interval}}

# Configure guardian (FREE, <1s)
config:
    @uv run python -m guardian config

# Check auth status (FREE, ~5s)
auth-status:
    @uv run python -m guardian auth-status

# Authenticate with a service (FREE, <1s)
auth service token='':
    @uv run python -m guardian auth {{service}} --token {{token}}

# Authenticate with test (FREE, <1s)
auth-test service token='':
    @uv run python -m guardian auth {{service}} --token {{token}} --test

# Start MCP server (FREE, long-running)
mcp:
    @uv run python -m guardian mcp

# Start web dashboard (FREE, long-running)
dashboard host='' port='':
    @uv run python -m guardian dashboard --host {{host}} --port {{port}}

# Initialize monitoring spec (FREE, <1s)
spec-init:
    @uv run python -m guardian spec --init

# Generate spec from env (FREE, <1s)
spec-from-env:
    @uv run python -m guardian spec --from-env

# Edit monitoring spec (FREE, <1s)
spec-edit:
    @uv run python -m guardian spec --edit

# Show current spec (FREE, <1s)
spec:
    @uv run python -m guardian spec

# Auto-discover resources (FREE, ~10s)
discover spec='guardian.spec.yaml' base-path='' json='false' update-env='false':
    @uv run python -m guardian discover --spec {{spec}} --base-path {{base-path}} --json {{json}} --update-env {{update-env}}

# Show monitoring stats (FREE, ~30s)
stats:
    @uv run python -m guardian stats

# Show live monitoring stats (FREE, continuous)
stats-live:
    @uv run python -m guardian stats --live

# Run tests (FREE, ~10s)
test:
    @uv run pytest tests/ -v

# Run tests with coverage (FREE, ~15s)
coverage:
    @uv run pytest tests/ --cov=guardian --cov-report=html --cov-report=term

# Lint code (FREE, <5s)
lint:
    @uv run ruff check guardian/ tests/

# Format code (FREE, <5s)
format:
    @uv run ruff format guardian/ tests/

# Type check (FREE, ~10s)
type-check:
    @uv run mypy guardian/

# Run all quality checks (FREE, ~30s)
quality: lint type-check test

# Install dependencies (FREE, ~30s)
install:
    @uv pip install -e .

# Install dev dependencies (FREE, ~30s)
install-dev:
    @uv pip install -e ".[dev]"

# =============================================================================
# Dogfood (local) sweeps
# =============================================================================

# Run all enabled sweeps from a spec (bounded; non-destructive)
sweep spec='guardian.spec.yaml' dev-root='':
    @uv run python -m guardian sweep --spec {{spec}} --dev-root {{dev-root}}

# Scan *your* public GitHub repos for leaks (redacted JSON output)
sweep-public spec='guardian.spec.yaml':
    @uv run python -m guardian sweep --spec {{spec}} --only public_github_secrets
    @python3 -c 'import json; from pathlib import Path; p=Path(".state/guardian/public-github-leak-scan.json"); j=json.loads(p.read_text()); print("owners_expanded", j.get("scope",{}).get("owners_expanded")); print("repos_scanned_count", j.get("scope",{}).get("repos_scanned_count")); print("findings_total", j.get("summary",{}).get("findings_total")); print("errors_count", len(j.get("errors",[]))); print("engine", {k:j.get("engine",{}).get(k) for k in ["max_concurrency","per_repo_timeout_s"]})'

# Faster smoke run (scan fewer repos)
sweep-public-fast:
    @uv run python -m guardian sweep --spec guardian.spec.fast.yaml --only public_github_secrets
    @python3 -c 'import json; from pathlib import Path; p=Path(".state/guardian/public-github-leak-scan.fast.json"); j=json.loads(p.read_text()); print("owners_expanded", j.get("scope",{}).get("owners_expanded")); print("repos_scanned_count", j.get("scope",{}).get("repos_scanned_count")); print("findings_total", j.get("summary",{}).get("findings_total")); print("errors_count", len(j.get("errors",[]))); print("engine", {k:j.get("engine",{}).get(k) for k in ["max_concurrency","per_repo_timeout_s"]})'

# Scan *dirty* local worktrees (untracked/modified), redacted output
sweep-dirty:
    @uv run python -m guardian sweep --spec guardian.spec.yaml --only local_dirty_worktree_secrets

# Audit .gitignore files across dev repos for missing patterns
sweep-gitignore:
    @uv run python -m guardian sweep --spec guardian.spec.yaml --only gitignore_audit

# Audit dependencies for known vulnerabilities
sweep-deps:
    @uv run python -m guardian sweep --spec guardian.spec.yaml --only dependency_audit

# Audit AI editor configs (Claude, Cursor, Copilot, MCP) across repos
sweep-ai-editor:
    @uv run python -m guardian sweep --spec guardian.spec.yaml --only ai_editor_config_audit

# Audit cargo publish pipelines (tags, OIDC, dry-run, version consistency)
sweep-cargo-publish:
    @uv run python -m guardian sweep --spec guardian.spec.yaml --only cargo_publish_audit

# Audit SSH keys for weak algorithms, missing passphrases, stale registrations
sweep-ssh:
    @uv run python -m guardian sweep --spec guardian.spec.yaml --only ssh_key_audit