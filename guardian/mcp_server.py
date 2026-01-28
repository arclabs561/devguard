"""MCP Server for Guardian.

This module exposes Guardian's capabilities as a Model Context Protocol (MCP) server,
allowing AI assistants to directly run security checks and retrieve reports.
"""

import json
import logging

from mcp.server.fastmcp import FastMCP

from guardian.config import get_settings
from guardian.core import Guardian
from guardian.models import GuardianReport
from guardian.reporting import Reporter

# Initialize FastMCP server
mcp = FastMCP("guardian")
logger = logging.getLogger(__name__)


@mcp.tool()
async def run_checks(
    json_output: bool = True,
    npm_packages: list[str] | None = None,
    github_repos: list[str] | None = None,
) -> str:
    """Run security checks and return the report.

    Args:
        json_output: Whether to return JSON (default: True)
        npm_packages: Optional list of npm packages to check (overrides config)
        github_repos: Optional list of GitHub repos to check (overrides config)
    """
    # Validate inputs to prevent injection or malicious patterns
    if npm_packages:
        for pkg in npm_packages:
            if not pkg or any(c in pkg for c in [";", "&", "|", "`", "$"]):
                return json.dumps({"error": f"Invalid package name: {pkg}"})

    if github_repos:
        for repo in github_repos:
            if not repo or not all(c.isalnum() or c in "/-._" for c in repo):
                return json.dumps({"error": f"Invalid repo format: {repo}"})

    settings = get_settings()

    # Override settings if provided
    if npm_packages:
        settings.npm_packages_to_monitor = npm_packages
    if github_repos:
        settings.github_repos_to_monitor = github_repos

    guardian = Guardian(settings)
    report = await guardian.run_checks()

    if json_output:
        # Convert to dict for JSON serialization
        reporter = Reporter(settings)
        # We redact sensitive info before returning via MCP
        report_dict = reporter._report_to_dict(report)
        return json.dumps(report_dict, indent=2)

    return _format_text_report(report)


@mcp.tool()
async def scan_npm_package(package_name: str) -> str:
    """Deep scan a specific npm package for vulnerabilities.

    Args:
        package_name: The name of the npm package to scan
    """
    settings = get_settings()
    # Enable deep security scanning
    settings.npm_security_enabled = True
    settings.npm_packages_to_monitor = [package_name]

    guardian = Guardian(settings)

    # Run only the npm checker using the new checker_types parameter
    report = await guardian.run_checks(checker_types=["npm"])

    # Get npm results (should be only one)
    npm_checks = [c for c in report.checks if c.check_type == "npm"]
    if not npm_checks:
        return f"No results found for {package_name}"

    result = npm_checks[0]
    return json.dumps(
        {
            "success": result.success,
            "vulnerabilities": [v.model_dump() for v in result.vulnerabilities],
            "metadata": result.metadata,
        },
        indent=2,
    )


@mcp.tool()
async def get_email_history(limit: int = 10) -> str:
    """Get recent email alert history for introspection.

    Returns JSON array of recent emails with their summaries, issues, and metadata.
    If USE_SMART_EMAIL is enabled, reads from unified SQLite database (includes Guardian + agent alerts).
    Otherwise, reads from Guardian's JSON history.

    Useful for agents to understand email patterns and decide when/how to send alerts.

    Args:
        limit: Maximum number of recent emails to return (default: 10, max: 100)
    """
    from guardian.reporting import Reporter

    settings = get_settings()
    reporter = Reporter(settings)
    history = reporter.get_email_history(limit=min(limit, 100))

    return json.dumps(history, indent=2, default=str)


@mcp.tool()
async def get_unified_alert_history(limit: int = 20, topic: str | None = None) -> str:
    """Get unified alert history from smart_email system (all agents + Guardian).

    Returns alerts from all sources (Guardian, SRE Agent, Watchdog, etc.) in a unified format.
    Only works if smart_email system is available.

    Args:
        limit: Maximum number of alerts to return (default: 20, max: 100)
        topic: Optional topic filter (e.g., 'security_posture', 'cost_anomaly')
    """
    settings = get_settings()
    use_smart_email = getattr(settings, "use_smart_email", False)

    if not use_smart_email:
        return json.dumps(
            {
                "error": "smart_email not enabled. Set USE_SMART_EMAIL=true to use unified history.",
                "fallback": "Use get_email_history() for Guardian-only history",
            },
            indent=2,
        )

    try:
        import sqlite3

        from guardian.utils import get_smart_email_db_path, import_smart_email

        smart_email = import_smart_email()
        if not smart_email:
            return json.dumps(
                {
                    "error": "smart_email not enabled. Set USE_SMART_EMAIL=true to use unified history.",
                    "fallback": "Use get_email_history() for Guardian-only history",
                },
                indent=2,
            )

        init_db = smart_email.init_db
        db_path = get_smart_email_db_path(settings)

        init_db(db_path)
        conn = sqlite3.connect(str(db_path))

        # Query all alerts (optionally filtered by topic)
        if topic:
            rows = conn.execute(
                """
                SELECT topic, severity, subject, sent_at, author, metadata_json
                FROM alert_history
                WHERE topic LIKE ?
                ORDER BY sent_at DESC
                LIMIT ?
            """,
                (f"%{topic}%", min(limit, 100)),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT topic, severity, subject, sent_at, author, metadata_json
                FROM alert_history
                ORDER BY sent_at DESC
                LIMIT ?
            """,
                (min(limit, 100),),
            ).fetchall()

        conn.close()

        # Convert to unified format with all preserved metadata
        alerts = []
        for row in rows:
            if len(row) >= 7:  # New format with message_preview
                topic_val, severity, subject, sent_at, author, message_preview, metadata_json = row
            else:  # Old format without message_preview
                topic_val, severity, subject, sent_at, author, metadata_json = row[:6]
                message_preview = ""

            metadata = json.loads(metadata_json) if metadata_json else {}

            # Extract all useful information for analysis
            alert_entry = {
                "timestamp": sent_at,
                "topic": topic_val,
                "severity": severity,
                "subject": subject,
                "author": author or "unknown",
                "message_preview": message_preview,
                "summary": metadata.get("summary", {}),
                "issues": metadata.get("issues", {}),
                "llm_decision": metadata.get("llm_decision"),
                "llm_reasoning": metadata.get("llm_reasoning", {}),
                "report_summary": metadata.get("report_summary", {}),
                "actionable": metadata.get("actionable", False),
                "context": metadata.get("context", {}),  # Alert context (occurrence counts, trends)
                "full_metadata": metadata,  # Complete metadata for deep analysis
            }

            alerts.append(alert_entry)

        return json.dumps({"total": len(alerts), "alerts": alerts}, indent=2, default=str)

    except Exception as e:
        logger.error(f"Failed to get unified alert history: {e}")
        return json.dumps(
            {"error": str(e), "message": "Could not read from smart_email database"}, indent=2
        )


def _format_text_report(report: GuardianReport) -> str:
    """Format report as text."""
    lines = ["Guardian Security Report", "=" * 24, ""]

    summary = report.summary
    lines.append(f"Total Checks: {summary.get('total_checks', 0)}")
    lines.append(f"Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
    lines.append(f"Critical: {summary.get('critical_vulnerabilities', 0)}")
    lines.append("")

    for check in report.checks:
        status = "✓" if check.success else "✗"
        lines.append(f"[{status}] {check.check_type.upper()}")

        for vuln in check.vulnerabilities:
            lines.append(f"  - [{vuln.severity}] {vuln.summary}")
            if vuln.description:
                lines.append(f"    {vuln.description}")

        if check.errors:
            for error in check.errors:
                lines.append(f"  ! {error}")

    return "\n".join(lines)


def run_mcp_server():
    """Run the MCP server."""
    mcp.run()
