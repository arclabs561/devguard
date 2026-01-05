# Guardian

Unified monitoring for npm packages, GitHub repositories, and Fly.io/Vercel deployments.

## Overview

Guardian provides a single tool to monitor:
- **npm packages** for security vulnerabilities
- **GitHub repositories** for Dependabot security alerts
- **Fly.io deployments** for health status
- **Vercel deployments** for deployment status
- **Container/Dockerfile** security best practices
- **Secret Scanning** (with TruffleHog integration or regex fallback)
- **AWS IAM** security posture for satellite nodes
- **AWS Cost** monitoring with budget alerts
- **Firecrawl API** for credit usage monitoring
- **Tavily API** for usage tracking
- **API Usage/Credits** for LLM providers (OpenRouter, Anthropic, OpenAI, Perplexity, Groq)
- **Tailscale** mesh network health
- **Domain/SSL** certificate expiry monitoring
- **Docker Swarm** cluster health and placement constraint compliance
- **Red Team Security Testing** for deployment endpoints (automated security scanning)
- **Web Dashboard** for real-time monitoring visualization
- **Model Context Protocol (MCP)** server for AI agent integration

## Installation

```bash
# Using uv (recommended)
uv pip install -e .

# Or using pip
pip install -e .
```

## Configuration

1. Copy `.env.example` to `.env` (if it exists, or create one)
2. Set required environment variables:

```bash
# Required
GITHUB_TOKEN=your_github_token
VERCEL_TOKEN=your_vercel_token

# Optional
FLY_API_TOKEN=your_fly_token
SNYK_TOKEN=your_snyk_token
GITHUB_ORG=your_org_name
NPM_PACKAGES_TO_MONITOR=package1,package2
GITHUB_REPOS_TO_MONITOR=owner/repo1,owner/repo2
FLY_APPS_TO_MONITOR=app1,app2
VERCEL_PROJECTS_TO_MONITOR=project1,project2

# Security Scanners
SECRET_SCAN_ENABLED=true
CONTAINER_CHECK_ENABLED=true
NPM_SECURITY_ENABLED=true
AWS_IAM_CHECK_ENABLED=false  # Enable for AWS satellite node IAM checks

# Additional Service API Keys
FIRECRAWL_API_KEY=your_firecrawl_key
TAVILY_API_KEY=your_tavily_key

# Dashboard Configuration
DASHBOARD_ENABLED=false
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=8080
DASHBOARD_API_KEY=your_secure_key  # Generate with: openssl rand -hex 32
ALLOWED_ORIGINS=http://localhost:3000  # Optional, comma-separated

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000

# Environment
ENVIRONMENT=development  # or "production"
```

## Security Testing

Guardian includes multiple layers of security testing:

### 1. Model Context Protocol (MCP) Server

Guardian acts as an MCP server, allowing AI assistants (like Claude, Cursor) to directly perform security audits.

```bash
# Start the MCP server
guardian mcp
```

### 2. Container & Dockerfile Security

Automatically scans `Dockerfile`s for best practices:
- Running as root
- Using `latest` tag
- Exposed secrets
- Missing `HEALTHCHECK`
- Usage of `sudo`

### 3. Secret Scanning

Scans git history and files for secrets.
- Uses **TruffleHog** if installed (recommended for high accuracy).
- Falls back to **Regex Scanning** if TruffleHog is missing (checks for common keys like AWS, GitHub, Stripe).

### 4. Red Team Security Testing (Deployments)

Automated red team security testing for your Fly.io and Vercel deployments. Checks for:
- Missing security headers
- Exposed admin endpoints
- CORS misconfigurations
- Information disclosure

### 5. Deep npm Package Security Analysis

Guardian can perform deep security analysis of your published npm packages, checking for:
- Secrets and credentials
- Obfuscated code
- Sensitive files
- Git history
- Missing .npmignore

### 6. AWS IAM Security Checks

For infrastructure with AWS satellite nodes (EC2 instances with IAM roles), Guardian can verify:
- No overly broad policies (AdministratorAccess, S3FullAccess, etc.)
- IAM role configuration matches expected posture
- No credential files on EC2 instances (via SSM)

Configuration is loaded from `ops/security/iam-posture.yaml` if present, otherwise uses defaults.

Enable with: `AWS_IAM_CHECK_ENABLED=true`

## Usage

### Run checks once

```bash
guardian check
```

### Run checks in watch mode

```bash
guardian check --watch
```

### Start MCP Server

```bash
guardian mcp
```

### Web Dashboard

```bash
guardian dashboard
```

Starts a web dashboard server for real-time monitoring.

### CI/CD Integration

Guardian includes a GitHub Actions workflow example in `guardian/examples/github-workflow.yml`.

To use it, copy the file to your `.github/workflows/` directory.

## Architecture

Guardian uses a modular checker architecture with the following components:

### Core Components

- **Guardian**: Main orchestrator that manages checkers and generates reports
- **BaseChecker**: Abstract base class defining the interface for all checkers
- **Reporter**: Handles output formatting, webhooks, and email delivery
- **Settings**: Configuration management using Pydantic-Settings

### Checkers

- **NpmChecker**: Checks npm packages for vulnerabilities
- **GitHubChecker**: Checks GitHub repos for alerts
- **VercelChecker**: Checks Vercel deployment status
- **FlyChecker**: Checks Fly.io deployment health
- **ContainerChecker**: Checks Dockerfile security
- **SecretChecker**: Checks for leaked secrets
- **AWSIAMChecker**: Checks AWS IAM posture for satellite nodes
- **RedTeamChecker**: Active security scanning of endpoints

## API Tokens

### GitHub Token

Create a personal access token with:
- `repo` scope (for private repos)
- `security_events` scope (for Dependabot alerts)

### Vercel Token

Create a token at: https://vercel.com/account/tokens

### Fly.io Token

Create a token at: https://fly.io/user/personal_access_tokens

## Development

```bash
# Install dev dependencies
uv pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check .

# Run type checker
mypy guardian/
```

## License

MIT
