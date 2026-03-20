"""Configuration management for Guardian."""

from typing import Annotated

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),  # Load local first, then root fallback
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # GitHub Configuration
    github_token: SecretStr | None = Field(None, description="GitHub personal access token")
    github_org: str | None = Field(None, description="GitHub organization name (optional)")

    # Vercel Configuration
    vercel_token: SecretStr | None = Field(None, description="Vercel API token")
    vercel_team_id: str | None = Field(None, description="Vercel team ID (optional)")

    # Fly.io Configuration
    fly_api_token: SecretStr | None = Field(None, description="Fly.io API token")

    # npm/Snyk Configuration
    snyk_token: SecretStr | None = Field(None, description="Snyk API token (optional)")

    # Monitoring Configuration
    check_interval_seconds: int = Field(3600, description="Interval between checks in seconds")
    alert_webhook_url: SecretStr | None = Field(None, description="Webhook URL for alerts")
    alert_email: str | None = Field(None, description="Email address for alerts")
    environment: str = Field("development", description="Environment mode (development/production)")

    # Rate Limiting Configuration
    rate_limit_per_minute: int = Field(60, description="Maximum API calls per minute per service")
    rate_limit_per_hour: int = Field(1000, description="Maximum API calls per hour per service")

    # Red Team Security Testing
    redteam_enabled: bool = Field(
        True, description="Enable red team security testing for deployments"
    )

    # Deep npm Package Security Analysis
    npm_security_enabled: bool = Field(
        False,
        description="Enable deep security analysis of npm packages (secrets, obfuscation, etc.)",
    )

    # Dashboard Configuration
    dashboard_enabled: bool = Field(False, description="Enable web dashboard")
    dashboard_host: str = Field("0.0.0.0", description="Dashboard host to bind to")
    dashboard_port: int = Field(8080, description="Dashboard port")
    metrics_enabled: bool = Field(True, description="Enable Prometheus metrics")
    metrics_port: int = Field(9090, description="Prometheus metrics port")
    dashboard_api_key: SecretStr | None = Field(
        None, description="API key for dashboard access (generate with openssl rand -hex 32)"
    )
    allowed_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="Comma-separated list of allowed CORS origins",
    )

    # Additional Service API Keys
    firecrawl_api_key: SecretStr | None = Field(None, description="Firecrawl API key")
    tavily_api_key: SecretStr | None = Field(None, description="Tavily API key")
    anthropic_api_key: SecretStr | None = Field(None, description="Anthropic API key")
    openrouter_api_key: SecretStr | None = Field(None, description="OpenRouter API key")
    openai_api_key: SecretStr | None = Field(None, description="OpenAI API key")
    perplexity_api_key: SecretStr | None = Field(None, description="Perplexity API key")
    groq_api_key: SecretStr | None = Field(None, description="Groq API key")

    # SMTP Configuration (for email alerts)
    smtp_host: str | None = Field(None, description="SMTP server hostname")
    smtp_port: int = Field(587, description="SMTP server port")
    smtp_user: str | None = Field(None, description="SMTP username")
    smtp_password: SecretStr | None = Field(None, description="SMTP password")
    smtp_from: str | None = Field(None, description="From email address")
    smtp_use_tls: bool = Field(True, description="Use TLS for SMTP connection")
    email_only_on_issues: bool = Field(
        True, description="Only send emails when there are issues (skip 'all clear' reports)"
    )
    email_thread_id_file: str | None = Field(
        None,
        description="Path to file storing last email thread ID (default: .devguard-email-thread)",
    )
    email_history_file: str | None = Field(
        None,
        description="Path to JSON file storing email history for agent introspection (default: .devguard-email-history.json)",
    )
    email_llm_enabled: bool = Field(
        True,
        description="Enable LLM-powered email judgements (subject lines, send decisions, summaries). Defaults to True. Set to False to disable.",
    )
    use_smart_email: bool = Field(
        True,
        description="Use smart_email system (SNS) instead of direct SMTP. Provides batching, deduplication, and threading. Falls back to SMTP if smart_email unavailable.",
    )
    smart_email_db_path: str | None = Field(
        None,
        description="Path to smart_email SQLite database (default: /data/smart_email.db or SMART_EMAIL_DB env var)",
    )

    # Package Monitoring - use NoDecode to prevent JSON parsing,
    # validator handles comma-separated strings
    npm_packages_to_monitor: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="List of npm packages to monitor",
    )

    # Repository Monitoring
    github_repos_to_monitor: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="List of GitHub repos to monitor (owner/repo format)",
    )

    # Deployment Monitoring
    fly_apps_to_monitor: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="List of Fly.io apps to monitor",
    )
    vercel_projects_to_monitor: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="List of Vercel projects to monitor",
    )

    # Secret Scanning
    secret_scan_enabled: bool = Field(True, description="Enable secret scanning of git repos")
    secret_scan_paths: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="Paths to git repos to scan for secrets (default: _infra subprojects)",
    )

    # Container Security
    container_check_enabled: bool = Field(
        True, description="Enable Container/Dockerfile security checks"
    )

    # AWS IAM Security
    aws_iam_check_enabled: bool = Field(
        False, description="Enable AWS IAM security checks for satellite nodes"
    )

    # AWS Cost Monitoring
    aws_cost_check_enabled: bool = Field(
        False, description="Enable AWS cost monitoring and budget alerts"
    )
    aws_monthly_cost_ceiling: float = Field(
        100.0,
        description="AWS monthly cost ceiling in USD (alerts when exceeded). Reset to $100 Jan 2025. Matches ops/config/budget.yaml",
    )

    # Tailscale Network Health
    tailscale_check_enabled: bool = Field(
        False, description="Enable Tailscale mesh network health checks"
    )

    # Tailsnitch ACL Security Audit
    tailsnitch_check_enabled: bool = Field(
        False, description="Enable Tailsnitch security audit for Tailscale ACLs"
    )
    tailsnitch_binary_path: str | None = Field(
        None, description="Custom path to tailsnitch binary (auto-detected if not set)"
    )
    tailsnitch_tailnet: str | None = Field(
        None, description="Specific tailnet to audit (default: from API key)"
    )
    # Tailscale authentication (for Tailsnitch)
    # Note: Tailsnitch supports both API key and OAuth
    # API key: TSKEY or TS_API_KEY
    # OAuth: TS_OAUTH_CLIENT_ID + TS_OAUTH_CLIENT_SECRET
    # These are read from environment, not stored in Settings for security

    # Domain/SSL Monitoring
    domain_check_enabled: bool = Field(
        False, description="Enable domain and SSL certificate monitoring"
    )

    # Docker Swarm Health
    swarm_check_enabled: bool = Field(
        False, description="Enable Docker Swarm cluster health checks"
    )

    # API Usage/Credits Monitoring
    api_usage_check_enabled: bool = Field(
        False, description="Enable API usage/credits monitoring for LLM providers"
    )

    @field_validator(
        "npm_packages_to_monitor",
        "github_repos_to_monitor",
        "fly_apps_to_monitor",
        "vercel_projects_to_monitor",
        "allowed_origins",
        "secret_scan_paths",
        mode="before",
    )
    @classmethod
    def parse_comma_separated_string(cls, v: str | list[str] | None) -> list[str]:
        """Parse comma-separated strings into lists."""
        if v is None:
            return []
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        if isinstance(v, list):
            return v
        return []


def get_settings(env_file: str | None = None) -> Settings:
    """Get application settings.

    Args:
        env_file: Optional path to an env file to load (e.g. "../.env" when
            running Guardian from inside an infra repo). When not provided,
            the Settings `model_config.env_file` default is used.
    """
    if env_file:
        return Settings(_env_file=env_file)  # type: ignore[call-arg]
    return Settings()  # type: ignore[call-arg]
