"""Prometheus metrics exporter for devguard."""

import logging

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    start_http_server,
)

from devguard.models import GuardianReport

logger = logging.getLogger(__name__)

# Metrics definitions
check_total = Counter(
    "devguard_checks_total",
    "Total number of checks performed",
    ["check_type", "status"],
)

check_duration = Histogram(
    "devguard_check_duration_seconds",
    "Time spent performing checks",
    ["check_type"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0],
)

vulnerabilities_total = Gauge(
    "devguard_vulnerabilities_total",
    "Total number of vulnerabilities",
    ["check_type", "severity"],
)

deployments_total = Gauge(
    "devguard_deployments_total",
    "Total number of deployments",
    ["check_type", "status"],
)

repository_alerts_total = Gauge(
    "devguard_repository_alerts_total",
    "Total number of repository alerts",
    ["check_type", "state"],
)

# Cost metrics
service_cost = Gauge(
    "devguard_service_cost_usd",
    "Cost for a service in USD",
    ["service", "period"],
)

service_usage = Gauge(
    "devguard_service_usage",
    "Usage amount for a service",
    ["service", "unit"],
)

service_usage_percent = Gauge(
    "devguard_service_usage_percent",
    "Usage percentage for a service (0-100)",
    ["service"],
)

service_usage_limit = Gauge(
    "devguard_service_usage_limit",
    "Usage limit for a service",
    ["service", "unit"],
)

check_errors_total = Counter(
    "devguard_check_errors_total",
    "Total number of check errors",
    ["check_type", "error_type"],
)


def update_metrics_from_report(report: GuardianReport) -> None:
    """Update Prometheus metrics from a devguard report."""
    for check in report.checks:
        # Update check counters
        status = "success" if check.success else "failure"
        check_total.labels(check_type=check.check_type, status=status).inc()

        # Update vulnerability metrics
        for vuln in check.vulnerabilities:
            vulnerabilities_total.labels(
                check_type=check.check_type, severity=vuln.severity.value
            ).inc()

        # Update deployment metrics
        for deployment in check.deployments:
            deployments_total.labels(
                check_type=check.check_type, status=deployment.status.value
            ).inc()

        # Update repository alert metrics
        for alert in check.repository_alerts:
            repository_alerts_total.labels(check_type=check.check_type, state=alert.state).inc()

        # Update cost metrics
        for cost in check.cost_metrics:
            if cost.amount is not None:
                service_cost.labels(service=cost.service, period=cost.period).set(cost.amount)

            if cost.usage is not None:
                unit = cost.metadata.get("unit", "credits")
                service_usage.labels(service=cost.service, unit=unit).set(cost.usage)

            if cost.usage_percent is not None:
                service_usage_percent.labels(service=cost.service).set(cost.usage_percent)

            if cost.limit is not None:
                unit = cost.metadata.get("unit", "credits")
                service_usage_limit.labels(service=cost.service, unit=unit).set(cost.limit)

        # Update error metrics
        for error in check.errors:
            error_type = "unknown"
            if "HTTP" in error:
                error_type = "http"
            elif "Network" in error or "timeout" in error.lower():
                error_type = "network"
            elif "Authentication" in error or "Unauthorized" in error:
                error_type = "auth"
            check_errors_total.labels(check_type=check.check_type, error_type=error_type).inc()


def get_metrics() -> bytes:
    """Get Prometheus metrics in text format."""
    return generate_latest()


def start_metrics_server(port: int = 9090) -> None:
    """Start Prometheus metrics HTTP server."""
    try:
        start_http_server(port)
        logger.info(f"Prometheus metrics server started on port {port}")
    except OSError as e:
        logger.error(f"Failed to start metrics server on port {port}: {e}")
        raise
