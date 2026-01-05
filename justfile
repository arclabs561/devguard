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

