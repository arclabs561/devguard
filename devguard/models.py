"""Data models for devguard monitoring results."""

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vulnerability severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    WARNING = "warning"  # For informational findings that aren't vulnerabilities


class CheckStatus(str, Enum):
    """Status of a health check."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"
    DEGRADED = "degraded"


class CostMetric(BaseModel):
    """Represents cost/usage metrics for a service."""

    service: str  # "vercel", "fly", "firecrawl", "tavily", etc.
    period: str  # "daily", "monthly", "billing_period"
    amount: float | None = None  # Cost in USD
    usage: float | None = None  # Usage amount (credits, requests, etc.)
    limit: float | None = None  # Usage limit
    usage_percent: float | None = None  # Usage percentage (0-100)
    currency: str = "USD"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)


class Vulnerability(BaseModel):
    """Represents a security vulnerability."""

    package_name: str
    package_version: str
    severity: Severity
    advisory_id: str | None = None
    cve_id: str | None = None
    summary: str | None = None
    description: str | None = None
    first_patched_version: str | None = None
    vulnerable_version_range: str | None = None
    published_at: datetime | None = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str  # "npm", "gh", "snyk", etc.
    references: list[str] = Field(default_factory=list)  # URLs to documentation/advisories


class Finding(BaseModel):
    """Represents a security finding (more general than a vulnerability).

    Used for IAM issues, configuration problems, and other security concerns
    that don't fit the package-based vulnerability model.
    """

    severity: Severity
    title: str
    description: str
    resource: str  # The resource being checked (role name, instance ID, etc.)
    remediation: str | None = None  # Suggested fix
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)


class APIUsage(BaseModel):
    """API usage/credits for a service provider."""

    service: str  # "openrouter", "anthropic", "openai", "perplexity", "groq"
    credits_total: float | None = None  # Total credits purchased
    credits_used: float | None = None  # Credits consumed
    credits_remaining: float | None = None  # Credits left
    usage_percent: float = 0.0  # Percentage used (0-100)
    period_start: str | None = None  # Start of usage period
    period_end: str | None = None  # End of usage period
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)


class DeploymentStatus(BaseModel):
    """Status of a deployment."""

    platform: str  # "vercel", "fly"
    project_name: str
    deployment_id: str
    status: CheckStatus
    url: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    health_check_status: CheckStatus | None = None
    error_message: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RepositoryAlert(BaseModel):
    """Security alert from a GitHub repository."""

    repository: str  # "owner/repo"
    alert_id: int
    state: str  # "open", "dismissed", "fixed"
    severity: Severity
    dependency: dict[str, Any]
    security_advisory: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    dismissed_at: datetime | None = None
    fixed_at: datetime | None = None


class CheckResult(BaseModel):
    """Result of a monitoring check."""

    check_type: str  # "npm", "gh", "fly", "vercel", "aws_iam"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    success: bool
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    deployments: list[DeploymentStatus] = Field(default_factory=list)
    repository_alerts: list[RepositoryAlert] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)  # General security findings
    errors: list[str] = Field(default_factory=list)
    cost_metrics: list[CostMetric] = Field(default_factory=list)
    api_usage: list[APIUsage] = Field(default_factory=list)  # API credits/usage
    metadata: dict[str, Any] = Field(default_factory=dict)


class GuardianReport(BaseModel):
    """Unified report from all monitoring checks."""

    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    checks: list[CheckResult] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)

    def get_total_vulnerabilities(self) -> int:
        """Get total number of vulnerabilities across all checks."""
        return sum(len(check.vulnerabilities) for check in self.checks)

    def get_critical_vulnerabilities(self) -> list[Vulnerability]:
        """Get all critical vulnerabilities."""
        critical = []
        for check in self.checks:
            critical.extend([v for v in check.vulnerabilities if v.severity == Severity.CRITICAL])
        return critical

    def get_unhealthy_deployments(self) -> list[DeploymentStatus]:
        """Get all unhealthy deployments."""
        unhealthy = []
        for check in self.checks:
            unhealthy.extend([d for d in check.deployments if d.status != CheckStatus.HEALTHY])
        return unhealthy

    def get_open_repository_alerts(self) -> list[RepositoryAlert]:
        """Get all open repository security alerts."""
        open_alerts = []
        for check in self.checks:
            open_alerts.extend([a for a in check.repository_alerts if a.state == "open"])
        return open_alerts

    def get_total_cost(self) -> float:
        """Get total cost across all services."""
        total = 0.0
        for check in self.checks:
            for cost in check.cost_metrics:
                if cost.amount is not None:
                    total += cost.amount
        return total

    def get_cost_metrics(self) -> list[CostMetric]:
        """Get all cost metrics."""
        metrics = []
        for check in self.checks:
            metrics.extend(check.cost_metrics)
        return metrics

    def get_total_findings(self) -> int:
        """Get total number of findings across all checks."""
        return sum(len(check.findings) for check in self.checks)

    def get_critical_findings(self) -> list[Finding]:
        """Get all critical findings."""
        critical = []
        for check in self.checks:
            critical.extend([f for f in check.findings if f.severity == Severity.CRITICAL])
        return critical

    def get_high_findings(self) -> list[Finding]:
        """Get all high severity findings."""
        high = []
        for check in self.checks:
            high.extend([f for f in check.findings if f.severity == Severity.HIGH])
        return high
