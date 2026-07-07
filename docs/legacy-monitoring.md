# Legacy Monitoring

`devguard` originally monitored npm packages, GitHub repositories, and
Fly.io/Vercel deployments. That code still exists, but the main workflow is now
`devguard sweep`.

## Commands

```bash
devguard check
devguard check --watch
devguard mcp
devguard dashboard
devguard discover
devguard config
devguard auth gh
devguard auth-status
```

## Monitored Services

- npm packages
- GitHub repositories
- Fly.io deployments
- Vercel deployments
- Container and Dockerfile checks
- Secret scanning
- AWS IAM checks
- AWS cost checks
- LLM provider usage checks
- Firecrawl and Tavily usage checks
- Tailscale checks
- Domain and SSL certificate checks
- Docker Swarm checks
- Deployment red-team checks
- Web dashboard
- MCP server

## Environment Variables

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

## Internal Shape

- `devguard.core`: orchestrates monitoring checks and reports.
- `devguard.checkers.base.BaseChecker`: base class for service checkers.
- `devguard.reporting`: output formatting, webhooks, and email delivery.
- `devguard.checkers.*`: npm, GitHub, Vercel, Fly.io, container, secret,
  AWS IAM, cost, usage, and deployment checks.
