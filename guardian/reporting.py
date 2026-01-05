"""Reporting and alerting functionality."""

import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

from guardian.config import Settings
from guardian.models import GuardianReport

logger = logging.getLogger(__name__)

# Lazy import to avoid dependency if not using LLM features
_llm_service = None


def _get_llm_service(settings: Settings):
    """Get LLM service instance (lazy import)."""
    global _llm_service
    if _llm_service is None and getattr(settings, "email_llm_enabled", False):
        try:
            # Try shared LLM service first (ops/agent/llm_service.py)
            from guardian.utils import import_llm_service

            LLMService = import_llm_service()
            if LLMService:
                _llm_service = LLMService(settings)
            else:
                # Fallback to local LLM service
                from guardian.llm_service import LLMService

                _llm_service = LLMService(settings)
        except (ImportError, ValueError):
            # Fallback to local LLM service
            try:
                from guardian.llm_service import LLMService

                _llm_service = LLMService(settings)
            except ImportError:
                logger.debug("LLM service dependencies not available")
    return _llm_service


class Reporter:
    """Handle reporting and alerting."""

    def __init__(self, settings: Settings):
        """Initialize reporter with settings."""
        self.settings = settings
        self._email_history: list[dict[str, Any]] = []

    async def report(self, report: GuardianReport) -> None:
        """Generate and send reports."""
        # Print to console
        self._print_report(report)

        # Send webhook if configured
        if self.settings.alert_webhook_url:
            await self._send_webhook(report)

        # Send email if configured
        if self.settings.alert_email:
            await self._send_email(report)

    def _print_report(self, report: GuardianReport) -> None:
        """Print report to console."""
        from rich.console import Console
        from rich.table import Table

        console = Console()

        console.print("\n[bold blue]Guardian Report[/bold blue]")
        console.print(f"Generated at: {report.generated_at.isoformat()}\n")

        # Summary table
        summary_table = Table(title="Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="magenta")

        for key, value in report.summary.items():
            summary_table.add_row(key.replace("_", " ").title(), str(value))

        console.print(summary_table)
        console.print()

        # Critical vulnerabilities
        critical_vulns = report.get_critical_vulnerabilities()
        if critical_vulns:
            console.print(f"[bold red]Critical Vulnerabilities: {len(critical_vulns)}[/bold red]")
            for vuln in critical_vulns[:10]:  # Show first 10
                console.print(
                    f"  • {vuln.package_name}@{vuln.package_version} "
                    f"({vuln.severity.value}) - {vuln.summary or 'No summary'}"
                )
            console.print()

        # Unhealthy deployments
        unhealthy = report.get_unhealthy_deployments()
        if unhealthy:
            console.print(f"[bold red]Unhealthy Deployments: {len(unhealthy)}[/bold red]")
            for deployment in unhealthy:
                console.print(
                    f"  • {deployment.platform}/{deployment.project_name}: "
                    f"{deployment.status.value}"
                )
                if deployment.error_message:
                    console.print(f"    Error: {deployment.error_message}")
            console.print()

        # Open repository alerts
        open_alerts = report.get_open_repository_alerts()
        if open_alerts:
            console.print(f"[bold yellow]Open Repository Alerts: {len(open_alerts)}[/bold yellow]")
            for alert in open_alerts[:10]:  # Show first 10
                console.print(
                    f"  • {alert.repository}: {alert.severity.value} - "
                    f"{alert.security_advisory.get('summary', 'No summary')}"
                )
            console.print()

        # Check results
        for check in report.checks:
            status_style = "green" if check.success else "red"
            status_icon = "✓" if check.success else "✗"
            console.print(
                f"[{status_style}]{status_icon}[/{status_style}] "
                f"{check.check_type}: {len(check.errors)} errors"
            )

    async def _send_webhook(self, report: GuardianReport) -> None:
        """Send report to webhook URL."""
        if not self.settings.alert_webhook_url:
            return

        from guardian.http_client import create_client, retry_with_backoff

        payload = self._report_to_dict(report)

        try:

            async def send():
                async with create_client() as client:
                    response = await client.post(
                        self.settings.alert_webhook_url,
                        json=payload,
                    )
                    response.raise_for_status()
                    return response

            await retry_with_backoff(send, max_retries=2)
        except Exception as e:
            # Log but don't fail the entire report
            logger.warning(f"Failed to send webhook: {str(e)}")

    def _has_actionable_issues(self, report: GuardianReport) -> bool:
        """Check if report contains issues that warrant an email."""
        critical_vulns = len(report.get_critical_vulnerabilities())
        unhealthy = len(report.get_unhealthy_deployments())
        failed_checks = report.summary.get("failed_checks", 0)
        critical_findings = len(report.get_critical_findings())
        high_findings = len(report.get_high_findings())

        return (
            critical_vulns > 0
            or unhealthy > 0
            or failed_checks > 0
            or critical_findings > 0
            or high_findings > 0
        )

    def _get_thread_id_file(self) -> str:
        """Get path to thread ID storage file."""
        if self.settings.email_thread_id_file:
            return self.settings.email_thread_id_file
        # Default to .guardian-email-thread in current directory
        return os.path.join(os.getcwd(), ".guardian-email-thread")

    def _get_last_message_id(self) -> str | None:
        """Retrieve the last message ID from storage."""
        thread_file = self._get_thread_id_file()
        try:
            if os.path.exists(thread_file):
                with open(thread_file, "r") as f:
                    return f.read().strip() or None
        except Exception as e:
            logger.debug(f"Could not read thread ID file: {e}")
        return None

    def _save_message_id(self, message_id: str) -> None:
        """Save the message ID for threading."""
        thread_file = self._get_thread_id_file()
        try:
            os.makedirs(os.path.dirname(thread_file) or ".", exist_ok=True)
            with open(thread_file, "w") as f:
                f.write(message_id)
        except Exception as e:
            logger.debug(f"Could not write thread ID file: {e}")

    def _get_email_history_file(self) -> str:
        """Get path to email history storage file."""
        if self.settings.email_history_file:
            return self.settings.email_history_file
        # Default to .guardian-email-history.json in current directory
        return os.path.join(os.getcwd(), ".guardian-email-history.json")

    def _load_email_history(self) -> list[dict[str, Any]]:
        """Load email history from storage."""
        history_file = self._get_email_history_file()
        try:
            if os.path.exists(history_file):
                with open(history_file, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.debug(f"Could not read email history file: {e}")
        return []

    def _save_email_history(self, history: list[dict[str, Any]]) -> None:
        """Save email history to storage."""
        history_file = self._get_email_history_file()
        try:
            os.makedirs(os.path.dirname(history_file) or ".", exist_ok=True)
            # Keep only last 100 emails to prevent file from growing too large
            trimmed_history = history[-100:]
            with open(history_file, "w") as f:
                json.dump(trimmed_history, f, indent=2, default=str)
        except Exception as e:
            logger.debug(f"Could not write email history file: {e}")

    def _record_email_history(
        self,
        report: GuardianReport,
        message_id: str,
        subject: str,
        in_reply_to: str | None,
        llm_decision: dict[str, Any] | None = None,
    ) -> None:
        """Record email in history for agent introspection."""
        history = self._load_email_history()

        # Extract key information for agent decision-making
        critical_vulns = report.get_critical_vulnerabilities()
        high_findings = report.get_high_findings()
        critical_findings = report.get_critical_findings()
        unhealthy = report.get_unhealthy_deployments()

        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "message_id": message_id,
            "subject": subject,
            "in_reply_to": in_reply_to,
            "summary": {
                "critical_vulnerabilities": len(critical_vulns),
                "high_findings": len(high_findings),
                "critical_findings": len(critical_findings),
                "unhealthy_deployments": len(unhealthy),
                "total_vulnerabilities": report.summary.get("total_vulnerabilities", 0),
                "failed_checks": report.summary.get("failed_checks", 0),
                "total_checks": report.summary.get("total_checks", 0),
            },
            "issues": {
                "critical_vulns": [
                    {
                        "package": f"{v.package_name}@{v.package_version}",
                        "severity": v.severity.value,
                        "cve": v.cve_id,
                    }
                    for v in critical_vulns[:5]  # Top 5 for brevity
                ],
                "critical_findings": [
                    {
                        "title": f.title,
                        "resource": f.resource,
                        "check_type": next(
                            (c.check_type for c in report.checks if f in c.findings), "unknown"
                        ),
                    }
                    for f in critical_findings[:5]
                ],
                "high_findings": [
                    {
                        "title": f.title,
                        "resource": f.resource,
                        "check_type": next(
                            (c.check_type for c in report.checks if f in c.findings), "unknown"
                        ),
                    }
                    for f in high_findings[:5]
                ],
                "unhealthy_deployments": [
                    {
                        "platform": dep.platform,
                        "project": dep.project_name,
                        "status": dep.status.value,
                    }
                    for dep in unhealthy[:5]
                ],
            },
            "actionable": self._has_actionable_issues(report),
        }

        # Include LLM decision if available
        if llm_decision:
            entry["llm_decision"] = llm_decision

        history.append(entry)
        self._save_email_history(history)

        # Also write to smart_email SQLite if enabled (for unified history)
        use_smart_email = getattr(self.settings, "use_smart_email", False)
        if use_smart_email:
            try:
                from guardian.utils import import_smart_email, get_smart_email_db_path
                import sqlite3
                import hashlib

                smart_email = import_smart_email()
                if not smart_email:
                    logger.debug("smart_email module not available")
                    return

                init_db = smart_email.init_db
                normalize_topic = smart_email.normalize_topic
                get_thread_id = smart_email.get_thread_id

                # Get DB path
                db_path = get_smart_email_db_path(self.settings)

                init_db(db_path)
                conn = sqlite3.connect(str(db_path))

                # Determine severity from report
                critical_vulns = len(report.get_critical_vulnerabilities())
                critical_findings = len(report.get_critical_findings())
                high_findings = len(report.get_high_findings())
                unhealthy = len(report.get_unhealthy_deployments())

                if critical_vulns > 0 or critical_findings > 0 or unhealthy > 0:
                    severity = "CRITICAL"
                elif high_findings > 0:
                    severity = "HIGH"
                elif report.summary.get("total_vulnerabilities", 0) > 0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                topic = "security_posture"  # Canonical topic
                normalized = normalize_topic(topic)
                thread_id = get_thread_id(topic)

                # Create alert record with comprehensive metadata
                alert_id = hashlib.sha256(
                    f"{topic}:{entry['timestamp']}:guardian".encode()
                ).hexdigest()[:12]

                # Build comprehensive metadata for long-term analysis
                comprehensive_metadata = {
                    "summary": entry["summary"],
                    "issues": entry["issues"],
                    "llm_decision": entry.get("llm_decision"),
                    "author": "guardian",
                    "actionable": entry.get("actionable", False),
                    "message_id": entry.get("message_id"),
                    "in_reply_to": entry.get("in_reply_to"),
                    "report_timestamp": report.generated_at.isoformat(),
                    "check_types": [c.check_type for c in report.checks],
                    "total_checks": len(report.checks),
                    # Store full report summary for analysis
                    "report_summary": {
                        "total_vulnerabilities": report.summary.get("total_vulnerabilities", 0),
                        "total_checks": report.summary.get("total_checks", 0),
                        "successful_checks": report.summary.get("successful_checks", 0),
                        "failed_checks": report.summary.get("failed_checks", 0),
                    },
                }

                # Add LLM reasoning if available
                if llm_decision:
                    comprehensive_metadata["llm_reasoning"] = {
                        "should_send": llm_decision.get("should_send"),
                        "reasoning": llm_decision.get("reasoning"),
                        "priority": llm_decision.get("priority"),
                        "summary": llm_decision.get("summary"),
                    }

                message_preview = self._format_email_text(report)[:500]

                conn.execute(
                    """
                    INSERT OR REPLACE INTO alert_history 
                    (id, topic, severity, subject, sent_at, thread_id, occurrence_count, author, message_preview, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                    (
                        alert_id,
                        normalized,
                        severity,
                        subject,
                        entry["timestamp"],
                        thread_id,
                        "guardian",
                        message_preview,
                        json.dumps(comprehensive_metadata, default=str),
                    ),
                )

                conn.commit()
                conn.close()

            except Exception as e:
                logger.debug(f"Could not write to smart_email DB: {e}")

    def get_email_history(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get recent email history for agent introspection.

        Returns the most recent emails with their summaries and issues.
        Useful for agents to understand email patterns and decide when to send.

        If use_smart_email is enabled, reads from smart_email SQLite database.
        Otherwise, reads from JSON file.
        """
        use_smart_email = getattr(self.settings, "use_smart_email", False)

        if use_smart_email:
            # Try to read from smart_email SQLite
            try:
                from guardian.utils import import_smart_email, get_smart_email_db_path
                import sqlite3

                smart_email = import_smart_email()
                if not smart_email:
                    logger.debug("smart_email module not available, falling back to JSON")
                    history = self._load_email_history()
                    return history[-limit:] if limit else history

                init_db = smart_email.init_db
                db_path = get_smart_email_db_path(self.settings)

                init_db(db_path)
                conn = sqlite3.connect(str(db_path))

                # Query alert_history for Guardian emails (author='guardian')
                rows = conn.execute(
                    """
                    SELECT topic, severity, subject, sent_at, author, message_preview, metadata_json
                    FROM alert_history
                    WHERE author = 'guardian' OR topic = 'security_posture'
                    ORDER BY sent_at DESC
                    LIMIT ?
                """,
                    (limit,),
                ).fetchall()

                conn.close()

                # Convert to Guardian history format with all preserved metadata
                history = []
                for row in rows:
                    (
                        topic_val,
                        severity,
                        subject,
                        sent_at,
                        author,
                        message_preview,
                        metadata_json,
                    ) = row
                    metadata = json.loads(metadata_json) if metadata_json else {}
                    history.append(
                        {
                            "timestamp": sent_at,
                            "subject": subject,
                            "author": author or "guardian",
                            "severity": severity,
                            "topic": topic_val,
                            "message_preview": message_preview,
                            "summary": metadata.get("summary", {}),
                            "issues": metadata.get("issues", {}),
                            "llm_decision": metadata.get("llm_decision"),
                            "llm_reasoning": metadata.get("llm_reasoning"),
                            "report_summary": metadata.get("report_summary", {}),
                            "actionable": metadata.get("actionable", False),
                            "full_metadata": metadata,  # Preserve everything for deep analysis
                        }
                    )

                return history

            except Exception as e:
                logger.debug(f"Could not read from smart_email DB: {e}, falling back to JSON")

        # Fallback to JSON
        history = self._load_email_history()
        return history[-limit:] if limit else history

    def _generate_message_id(self, report: GuardianReport) -> str:
        """Generate a unique Message-ID for email threading."""
        import hashlib
        import time

        # Use timestamp and random component for unique Message-ID per email
        timestamp_ns = int(report.generated_at.timestamp() * 1e9)
        unique_hash = hashlib.md5(f"{timestamp_ns}-{time.time_ns()}".encode()).hexdigest()[:12]

        # Extract domain from From address for Message-ID
        smtp_from = getattr(self.settings, "smtp_from", "guardian@localhost")
        domain = smtp_from.split("@")[-1] if "@" in smtp_from else "localhost"

        message_id = f"<guardian-{unique_hash}@{domain}>"
        return message_id

    async def _send_email(self, report: GuardianReport) -> None:
        """
        Send report via email using smart_email (SNS) or SMTP.

        By default, uses smart_email system (SNS) with batching, deduplication, and threading.
        Falls back to direct SMTP if smart_email is unavailable.

        Configure via environment variables:
        - USE_SMART_EMAIL: Use smart_email system (default: true, falls back to SMTP if unavailable)
        - SMART_EMAIL_DB_PATH: Path to smart_email SQLite database
        - SMTP_HOST: SMTP server hostname (fallback if smart_email fails)
        - EMAIL_ONLY_ON_ISSUES: Only send emails when there are issues (default: True)
        """
        if not self.settings.alert_email:
            return

        # Check if we should send email (reduce noise)
        email_only_on_issues = getattr(self.settings, "email_only_on_issues", True)
        llm_enabled = getattr(self.settings, "email_llm_enabled", False)
        use_smart_email = getattr(self.settings, "use_smart_email", False)
        llm_decision: dict[str, Any] | None = None

        # Use LLM for send decision if enabled
        if llm_enabled:
            llm_service = _get_llm_service(self.settings)
            if llm_service:
                report_dict = self._report_to_dict(report)
                email_history = self.get_email_history(limit=10)
                llm_decision = await llm_service.should_send_email(report_dict, email_history)

                if not llm_decision.get("should_send", True):
                    logger.info(
                        f"Skipping email per LLM decision: {llm_decision.get('reasoning', 'No reason provided')}"
                    )
                    return
            elif email_only_on_issues and not self._has_actionable_issues(report):
                logger.debug("Skipping email: no actionable issues and email_only_on_issues=True")
                return
        elif email_only_on_issues and not self._has_actionable_issues(report):
            logger.debug("Skipping email: no actionable issues and email_only_on_issues=True")
            return

        # Try smart_email first if enabled
        if use_smart_email:
            try:
                success = await self._send_via_smart_email(report, llm_decision)
                if success:
                    return  # Successfully sent via smart_email
                logger.warning("smart_email send failed, falling back to SMTP")
            except Exception as e:
                logger.warning(f"smart_email error: {e}, falling back to SMTP")

        # Fallback to SMTP
        # Check if SMTP is configured
        smtp_host = getattr(self.settings, "smtp_host", None)
        smtp_user = getattr(self.settings, "smtp_user", None)
        smtp_password = getattr(self.settings, "smtp_password", None)
        smtp_from = getattr(self.settings, "smtp_from", None)

        if not all([smtp_host, smtp_user, smtp_password, smtp_from]):
            logger.warning(
                "Email sending requires SMTP configuration: "
                "smtp_host, smtp_user, smtp_password, smtp_from"
            )
            return

        try:
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            import aiosmtplib
        except ImportError:
            logger.warning("aiosmtplib not installed. Install with: pip install aiosmtplib")
            return

        try:
            smtp_port = getattr(self.settings, "smtp_port", 587)
            use_tls = getattr(self.settings, "smtp_use_tls", True)

            # Generate Message-ID for threading
            message_id = self._generate_message_id(report)
            last_message_id = self._get_last_message_id()

            # Generate subject line (LLM-powered if enabled)
            llm_enabled = getattr(self.settings, "email_llm_enabled", False)
            if llm_enabled:
                llm_service = _get_llm_service(self.settings)
                if llm_service:
                    report_dict = self._report_to_dict(report)
                    priority = report_dict.get("llm_decision", {}).get("priority", "medium")
                    try:
                        subject = await llm_service.generate_subject_line(report_dict, priority)
                    except Exception as e:
                        logger.warning(f"LLM subject generation failed: {e}, using fallback")
                        subject_suffix = self._generate_subject(report)
                        subject = f"Guardian Security Report - {subject_suffix}"
                else:
                    subject_suffix = self._generate_subject(report)
                    subject = f"Guardian Security Report - {subject_suffix}"
            else:
                subject_suffix = self._generate_subject(report)
                subject = f"Guardian Security Report - {subject_suffix}"

            # Create email message
            msg = MIMEMultipart("alternative")
            msg["From"] = smtp_from
            msg["To"] = self.settings.alert_email
            msg["Subject"] = subject
            msg["Message-ID"] = message_id

            # Set threading headers for proper email threading
            if last_message_id:
                msg["In-Reply-To"] = last_message_id
                msg["References"] = last_message_id

            # Create email body
            text_body = self._format_email_text(report)
            html_body = self._format_email_html(report)

            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            # Send email
            async with aiosmtplib.SMTP(hostname=smtp_host, port=smtp_port, use_tls=use_tls) as smtp:
                await smtp.login(smtp_user, smtp_password)
                await smtp.send_message(msg)

            # Save message ID for next email
            self._save_message_id(message_id)

            # Record email in history for agent introspection
            # llm_decision was already computed above if LLM is enabled
            self._record_email_history(report, message_id, subject, last_message_id, llm_decision)

            logger.info(f"Email sent successfully to {self.settings.alert_email}")

        except Exception as e:
            logger.warning(f"Failed to send email: {str(e)}")

    async def _send_via_smart_email(
        self, report: GuardianReport, llm_decision: dict[str, Any] | None = None
    ) -> bool:
        """
        Send report via smart_email system (SNS).

        Returns True if sent successfully, False otherwise.
        """
        try:
            from guardian.utils import import_smart_email, get_smart_email_db_path

            smart_email = import_smart_email()
            if not smart_email:
                logger.debug("smart_email module not available, falling back to SMTP")
                # Fallback handled in _send_email method
                return False

            smart_send_alert = smart_email.smart_send_alert
            db_path = get_smart_email_db_path(self.settings)

            # Convert report to format for smart_email
            report_dict = self._report_to_dict(report)
            summary = report_dict.get("summary", {})

            # Determine severity
            critical_vulns = summary.get("critical_vulnerabilities", 0)
            critical_findings = summary.get("critical_findings", 0)
            high_findings = summary.get("high_findings", 0)
            unhealthy = summary.get("unhealthy_deployments", 0)
            failed_checks = summary.get("failed_checks", 0)

            if critical_vulns > 0 or critical_findings > 0 or unhealthy > 0:
                severity = "CRITICAL"
            elif high_findings > 0 or failed_checks > 0:
                severity = "HIGH"
            elif summary.get("total_vulnerabilities", 0) > 0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            # Generate topic (normalized for threading)
            topic = "security_posture"  # Use canonical topic from smart_email

            # Generate headline/subject
            if llm_decision and llm_decision.get("summary"):
                headline = llm_decision["summary"]
            else:
                headline = self._generate_subject(report)

            # Generate message body (plain text version)
            message = self._format_email_text(report)

            # Truncate message if too long (SNS has limits)
            if len(message) > 4000:
                message = message[:3900] + "\n\n[Message truncated - see full report in dashboard]"

            # Determine if force immediate (CRITICAL/HIGH)
            force_immediate = severity in ("CRITICAL", "HIGH")

            # Build rich metadata for long-term analysis
            report_dict = self._report_to_dict(report)
            rich_metadata = {
                "llm_decision": llm_decision,
                "report_summary": report_dict.get("summary", {}),
                "report_checks": [
                    {
                        "check_type": c.check_type,
                        "success": c.success,
                        "vulnerabilities_count": len(c.vulnerabilities),
                        "findings_count": len(c.findings),
                    }
                    for c in report.checks
                ],
                "actionable_issues": self._has_actionable_issues(report),
                "report_generated_at": report.generated_at.isoformat(),
                "issues": {
                    "critical_vulns": [
                        {
                            "package": f"{v.package_name}@{v.package_version}",
                            "severity": v.severity.value,
                            "cve": v.cve_id,
                        }
                        for v in report.get_critical_vulnerabilities()[:5]
                    ],
                    "critical_findings": [
                        {
                            "title": f.title,
                            "resource": f.resource,
                            "check_type": next(
                                (c.check_type for c in report.checks if f in c.findings), "unknown"
                            ),
                        }
                        for f in report.get_critical_findings()[:5]
                    ],
                    "high_findings": [
                        {
                            "title": f.title,
                            "resource": f.resource,
                            "check_type": next(
                                (c.check_type for c in report.checks if f in c.findings), "unknown"
                            ),
                        }
                        for f in report.get_high_findings()[:5]
                    ],
                },
            }

            # Send via smart_email (with optional LLM support)
            use_llm = getattr(self.settings, "email_llm_enabled", False)
            success = smart_send_alert(
                db_path=db_path,
                topic=topic,
                severity=severity,
                headline=f"Guardian Security Report - {headline}",
                message=message,
                author="guardian",
                force_immediate=force_immediate,
                use_llm=use_llm,
                llm_settings=self.settings if use_llm else None,
                rich_metadata=rich_metadata,
            )

            if success:
                logger.info(f"Email sent via smart_email (SNS) to {self.settings.alert_email}")
                # Record in history for introspection
                self._record_email_history(report, None, headline, None, llm_decision)

            return success

        except ImportError as e:
            logger.warning(f"smart_email not available: {e}")
            return False
        except Exception as e:
            logger.warning(f"smart_email send failed: {e}")
            return False

    def _generate_subject(self, report: GuardianReport) -> str:
        """Generate a descriptive subject line based on report severity.

        Uses consistent format for email threading while including status details.
        """
        critical_vulns = len(report.get_critical_vulnerabilities())
        unhealthy = len(report.get_unhealthy_deployments())
        total_vulns = report.summary.get("total_vulnerabilities", 0)
        failed_checks = report.summary.get("failed_checks", 0)

        # Determine urgency level
        if critical_vulns > 0 or unhealthy > 0 or failed_checks > 0:
            urgency = "URGENT"
        elif total_vulns > 0:
            urgency = "ALERT"
        else:
            urgency = "Status"

        parts = []

        if critical_vulns > 0:
            parts.append(f"{critical_vulns} critical")
        if unhealthy > 0:
            parts.append(f"{unhealthy} unhealthy")
        if total_vulns > 0 and critical_vulns == 0:
            parts.append(f"{total_vulns} vulnerabilities")
        if failed_checks > 0:
            parts.append(f"{failed_checks} failed checks")

        if not parts:  # No issues
            parts.append("All systems healthy")

        status_text = " | ".join(parts) if parts else "All clear"
        return f"{urgency}: {status_text}"

    def _format_email_text(self, report: GuardianReport) -> str:
        """Format report as plain text email."""
        # Format timestamp
        timestamp = report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")

        lines = [
            "GUARDIAN SECURITY REPORT",
            "=" * 60,
            f"Generated: {timestamp}",
            "",
        ]

        # Executive summary
        summary = report.summary
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 60)
        lines.append(f"Total Checks: {summary.get('total_checks', 0)}")
        lines.append(f"  ✓ Successful: {summary.get('successful_checks', 0)}")
        lines.append(f"  ✗ Failed: {summary.get('failed_checks', 0)}")
        lines.append("")

        # Critical issues first
        critical_vulns = report.get_critical_vulnerabilities()
        critical_findings = report.get_critical_findings()
        high_findings = report.get_high_findings()
        unhealthy = report.get_unhealthy_deployments()

        if critical_vulns or critical_findings or high_findings or unhealthy:
            lines.append("⚠ CRITICAL ISSUES REQUIRING IMMEDIATE ATTENTION")
            lines.append("-" * 60)

            if critical_vulns:
                lines.append(f"\nCritical Vulnerabilities ({len(critical_vulns)}):")
                for vuln in critical_vulns[:15]:
                    lines.append(f"  • {vuln.package_name}@{vuln.package_version}")
                    if vuln.cve_id:
                        lines.append(f"    CVE: {vuln.cve_id}")
                    if vuln.summary:
                        lines.append(f"    {vuln.summary}")
                    if vuln.first_patched_version:
                        lines.append(f"    Fix: Upgrade to {vuln.first_patched_version}")
                    if vuln.references:
                        lines.append(f"    Reference: {vuln.references[0]}")
                    lines.append("")

            if critical_findings:
                lines.append(f"\nCritical Security Findings ({len(critical_findings)}):")
                for check in report.checks:
                    for finding in check.findings:
                        if finding.severity.value == "critical":
                            lines.append(f"  • [{check.check_type.upper()}] {finding.title}")
                            lines.append(f"    Resource: {finding.resource}")
                            lines.append(f"    {finding.description}")
                            if finding.remediation:
                                lines.append(f"    Remediation: {finding.remediation}")
                            lines.append("")

            if high_findings:
                lines.append(f"\nHigh Priority Findings ({len(high_findings)}):")
                for check in report.checks:
                    for finding in check.findings:
                        if finding.severity.value == "high":
                            lines.append(f"  • [{check.check_type.upper()}] {finding.title}")
                            lines.append(f"    Resource: {finding.resource}")
                            lines.append(f"    {finding.description}")
                            if finding.remediation:
                                lines.append(f"    Remediation: {finding.remediation}")
                            lines.append("")

            if unhealthy:
                lines.append(f"\nUnhealthy Deployments ({len(unhealthy)}):")
                for dep in unhealthy:
                    lines.append(f"  • {dep.platform.upper()}/{dep.project_name}")
                    lines.append(f"    Status: {dep.status.value}")
                    if dep.url:
                        lines.append(f"    URL: {dep.url}")
                    if dep.error_message:
                        lines.append(f"    Error: {dep.error_message}")
                    lines.append("")

        # Other vulnerabilities
        all_vulns = []
        for check in report.checks:
            for vuln in check.vulnerabilities:
                if vuln.severity.value in ["high", "medium"]:
                    all_vulns.append((check.check_type, vuln))

        if all_vulns:
            lines.append(f"\nOther Vulnerabilities ({len(all_vulns)}):")
            for check_type, vuln in all_vulns[:10]:
                lines.append(
                    f"  • [{check_type}] {vuln.package_name}@{vuln.package_version} ({vuln.severity.value})"
                )
                if vuln.summary:
                    lines.append(f"    {vuln.summary}")

        # Repository alerts
        open_alerts = report.get_open_repository_alerts()
        if open_alerts:
            lines.append(f"\n\nOpen Repository Alerts ({len(open_alerts)}):")
            for alert in open_alerts[:10]:
                adv = alert.security_advisory
                lines.append(f"  • {alert.repository}: {alert.severity.value}")
                if adv.get("summary"):
                    lines.append(f"    {adv['summary']}")

        # Cost metrics
        cost_metrics = report.get_cost_metrics()
        if cost_metrics:
            total_cost = report.get_total_cost()
            lines.append(f"\n\nCOST METRICS")
            lines.append("-" * 60)
            lines.append(f"Total: ${total_cost:.2f} USD")
            for cost in cost_metrics:
                if cost.amount is not None:
                    lines.append(f"  • {cost.service}: ${cost.amount:.2f} ({cost.period})")
                    if cost.usage_percent is not None:
                        lines.append(f"    Usage: {cost.usage_percent:.1f}%")

        # API usage
        api_usage = []
        for check in report.checks:
            api_usage.extend(check.api_usage)

        if api_usage:
            lines.append(f"\n\nAPI USAGE")
            lines.append("-" * 60)
            for usage in api_usage:
                if usage.usage_percent is not None:
                    lines.append(f"  • {usage.service}: {usage.usage_percent:.1f}% used")
                    if usage.credits_remaining is not None:
                        lines.append(f"    Remaining: {usage.credits_remaining:.0f} credits")

        # Check status
        lines.append(f"\n\nCHECK STATUS")
        lines.append("-" * 60)
        for check in report.checks:
            status = "✓" if check.success else "✗"
            lines.append(f"  {status} {check.check_type.upper()}")
            if check.errors:
                for error in check.errors[:3]:
                    lines.append(f"    Error: {error}")

        lines.append("\n" + "=" * 60)
        lines.append("End of Report")

        return "\n".join(lines)

    def _format_email_html(self, report: GuardianReport) -> str:
        """Format report as HTML email with modern styling."""
        timestamp = report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        summary = report.summary

        # Determine overall status
        critical_vulns = report.get_critical_vulnerabilities()
        unhealthy = report.get_unhealthy_deployments()
        failed_checks = summary.get("failed_checks", 0)

        if critical_vulns or unhealthy or failed_checks > 0:
            status_color = "#d32f2f"
            status_text = "⚠ Action Required"
        elif summary.get("total_vulnerabilities", 0) > 0:
            status_color = "#f57c00"
            status_text = "⚠ Issues Detected"
        else:
            status_color = "#388e3c"
            status_text = "✓ All Systems Healthy"

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 28px;
            font-weight: 600;
        }}
        .status-badge {{
            display: inline-block;
            background: {status_color};
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 600;
            margin-top: 10px;
        }}
        .content {{
            padding: 40px 30px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin: 30px 0;
        }}
        .summary-card {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #667eea;
        }}
        .summary-card.critical {{
            border-left-color: #d32f2f;
            background: #ffebee;
        }}
        .summary-card.warning {{
            border-left-color: #f57c00;
            background: #fff3e0;
        }}
        .summary-card.success {{
            border-left-color: #388e3c;
            background: #e8f5e9;
        }}
        .summary-card h3 {{
            margin: 0 0 5px 0;
            font-size: 12px;
            text-transform: uppercase;
            color: #666;
            letter-spacing: 0.5px;
        }}
        .summary-card .value {{
            font-size: 24px;
            font-weight: 700;
            color: #333;
        }}
        .section {{
            margin: 40px 0;
        }}
        .section:first-of-type {{
            margin-top: 20px;
        }}
        .section h2 {{
            font-size: 22px;
            font-weight: 700;
            margin: 0 0 20px 0;
            padding-bottom: 12px;
            border-bottom: 3px solid #e0e0e0;
            letter-spacing: -0.3px;
        }}
        .section.critical h2 {{
            color: #d32f2f;
            border-bottom-color: #d32f2f;
            font-size: 24px;
        }}
        .section.warning h2 {{
            color: #f57c00;
            border-bottom-color: #f57c00;
            font-size: 22px;
        }}
        .vuln-item, .finding-item, .deployment-item {{
            background: #f8f9fa;
            padding: 18px;
            margin: 12px 0;
            border-radius: 6px;
            border-left: 4px solid #ddd;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .vuln-item.critical {{
            border-left-color: #d32f2f;
            background: #ffebee;
        }}
        .vuln-item.high {{
            border-left-color: #f57c00;
            background: #fff3e0;
        }}
        .vuln-item.medium {{
            border-left-color: #ffa726;
            background: #fff8e1;
        }}
        .deployment-item.unhealthy {{
            border-left-color: #d32f2f;
            background: #ffebee;
        }}
        .item-header {{
            font-weight: 700;
            font-size: 17px;
            margin-bottom: 10px;
            line-height: 1.4;
            color: #212121;
        }}
        .item-meta {{
            font-size: 13px;
            color: #666;
            margin: 6px 0;
            line-height: 1.5;
        }}
        .item-description {{
            margin: 12px 0;
            color: #555;
            line-height: 1.6;
            font-size: 14px;
        }}
        .item-remediation {{
            background: #e3f2fd;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            font-size: 13px;
        }}
        .item-remediation strong {{
            color: #1976d2;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            margin-left: 8px;
        }}
        .badge.critical {{
            background: #d32f2f;
            color: white;
        }}
        .badge.high {{
            background: #f57c00;
            color: white;
        }}
        .badge.medium {{
            background: #ffa726;
            color: white;
        }}
        .badge.low {{
            background: #9e9e9e;
            color: white;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #555;
            font-size: 13px;
            text-transform: uppercase;
        }}
        .progress-bar {{
            background: #e0e0e0;
            border-radius: 10px;
            height: 20px;
            overflow: hidden;
            margin: 5px 0;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #4caf50, #8bc34a);
            transition: width 0.3s;
        }}
        .progress-fill.warning {{
            background: linear-gradient(90deg, #ff9800, #ffa726);
        }}
        .progress-fill.danger {{
            background: linear-gradient(90deg, #f44336, #e91e63);
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 12px;
            border-top: 1px solid #e0e0e0;
        }}
        .timestamp {{
            color: #999;
            font-size: 13px;
            margin-top: 5px;
        }}
        a {{
            color: #667eea;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        @media (max-width: 600px) {{
            body {{
                padding: 10px;
            }}
            .summary-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Guardian Security Report</h1>
            <div class="status-badge">{status_text}</div>
            <div class="timestamp">{timestamp}</div>
        </div>
        
        <div class="content">
            <div class="summary-grid">
                <div class="summary-card {"critical" if summary.get("critical_vulnerabilities", 0) > 0 else "success"}">
                    <h3>Critical Vulnerabilities</h3>
                    <div class="value">{summary.get("critical_vulnerabilities", 0)}</div>
                </div>
                <div class="summary-card {"warning" if summary.get("total_vulnerabilities", 0) > 0 else "success"}">
                    <h3>Total Vulnerabilities</h3>
                    <div class="value">{summary.get("total_vulnerabilities", 0)}</div>
                </div>
                <div class="summary-card {"critical" if summary.get("unhealthy_deployments", 0) > 0 else "success"}">
                    <h3>Unhealthy Deployments</h3>
                    <div class="value">{summary.get("unhealthy_deployments", 0)}</div>
                </div>
                <div class="summary-card {"critical" if summary.get("failed_checks", 0) > 0 else "success"}">
                    <h3>Failed Checks</h3>
                    <div class="value">{summary.get("failed_checks", 0)}</div>
                </div>
                <div class="summary-card">
                    <h3>Total Checks</h3>
                    <div class="value">{summary.get("total_checks", 0)}</div>
                </div>
                <div class="summary-card">
                    <h3>Successful</h3>
                    <div class="value">{summary.get("successful_checks", 0)}</div>
                </div>
            </div>"""

        # Critical vulnerabilities
        if critical_vulns:
            html += f"""
            <div class="section critical">
                <h2>⚠ Critical Vulnerabilities ({len(critical_vulns)})</h2>"""
            for vuln in critical_vulns[:15]:
                severity_class = vuln.severity.value
                html += f"""
                <div class="vuln-item {severity_class}">
                    <div class="item-header">
                        {vuln.package_name}@{vuln.package_version}
                        <span class="badge {severity_class}">{vuln.severity.value}</span>
                    </div>"""
                if vuln.cve_id:
                    html += f'<div class="item-meta">CVE: {vuln.cve_id}</div>'
                if vuln.summary:
                    html += f'<div class="item-description">{vuln.summary}</div>'
                if vuln.first_patched_version:
                    html += f"""
                    <div class="item-remediation">
                        <strong>Remediation:</strong> Upgrade to {vuln.first_patched_version}
                    </div>"""
                if vuln.references:
                    html += f'<div class="item-meta"><a href="{vuln.references[0]}" target="_blank">View Advisory →</a></div>'
                html += "</div>"
            html += "</div>"

        # Critical findings
        critical_findings = report.get_critical_findings()
        if critical_findings:
            html += f"""
            <div class="section critical">
                <h2>⚠ Critical Security Findings ({len(critical_findings)})</h2>"""
            for check in report.checks:
                for finding in check.findings:
                    if finding.severity.value == "critical":
                        html += f"""
                        <div class="finding-item">
                            <div class="item-header">
                                <span class="badge" style="background: #9e9e9e; margin-right: 8px;">{check.check_type.upper()}</span>
                                {finding.title}
                            </div>
                            <div class="item-meta">Resource: {finding.resource}</div>
                            <div class="item-description">{finding.description}</div>"""
                        if finding.remediation:
                            html += f"""
                            <div class="item-remediation">
                                <strong>Remediation:</strong> {finding.remediation}
                            </div>"""
                        html += "</div>"
            html += "</div>"

        # High findings (Swarm, AWS, etc.)
        high_findings = report.get_high_findings()
        if high_findings:
            html += f"""
            <div class="section warning">
                <h2>⚠ High Priority Findings ({len(high_findings)})</h2>"""
            for check in report.checks:
                for finding in check.findings:
                    if finding.severity.value == "high":
                        html += f"""
                        <div class="finding-item">
                            <div class="item-header">
                                <span class="badge" style="background: #9e9e9e; margin-right: 8px;">{check.check_type.upper()}</span>
                                {finding.title}
                            </div>
                            <div class="item-meta">Resource: {finding.resource}</div>
                            <div class="item-description">{finding.description}</div>"""
                        if finding.remediation:
                            html += f"""
                            <div class="item-remediation">
                                <strong>Remediation:</strong> {finding.remediation}
                            </div>"""
                        html += "</div>"
            html += "</div>"

        # Unhealthy deployments
        if unhealthy:
            html += f"""
            <div class="section critical">
                <h2>⚠ Unhealthy Deployments ({len(unhealthy)})</h2>"""
            for dep in unhealthy:
                platform_display = (
                    dep.platform.upper() if dep.platform in ["swarm", "aws"] else dep.platform
                )
                html += f"""
                <div class="deployment-item unhealthy">
                    <div class="item-header">
                        <span class="badge" style="background: #9e9e9e; margin-right: 8px;">{platform_display}</span>
                        {dep.project_name}
                    </div>
                    <div class="item-meta">Status: {dep.status.value}</div>"""
                if dep.url:
                    html += f'<div class="item-meta"><a href="{dep.url}" target="_blank">{dep.url}</a></div>'
                if dep.error_message:
                    html += f'<div class="item-description" style="color: #d32f2f;">Error: {dep.error_message}</div>'
                html += "</div>"
            html += "</div>"

        # Other vulnerabilities
        other_vulns = []
        for check in report.checks:
            for vuln in check.vulnerabilities:
                if vuln.severity.value in ["high", "medium"]:
                    other_vulns.append((check.check_type, vuln))

        if other_vulns:
            html += f"""
            <div class="section warning">
                <h2>Other Vulnerabilities ({len(other_vulns)})</h2>"""
            for check_type, vuln in other_vulns[:10]:
                severity_class = vuln.severity.value
                html += f"""
                <div class="vuln-item {severity_class}">
                    <div class="item-header">
                        [{check_type}] {vuln.package_name}@{vuln.package_version}
                        <span class="badge {severity_class}">{vuln.severity.value}</span>
                    </div>"""
                if vuln.summary:
                    html += f'<div class="item-description">{vuln.summary}</div>'
                html += "</div>"
            html += "</div>"

        # Repository alerts
        open_alerts = report.get_open_repository_alerts()
        if open_alerts:
            html += f"""
            <div class="section warning">
                <h2>Open Repository Alerts ({len(open_alerts)})</h2>"""
            for alert in open_alerts[:10]:
                adv = alert.security_advisory
                severity_class = alert.severity.value
                html += f"""
                <div class="vuln-item {severity_class}">
                    <div class="item-header">
                        {alert.repository}
                        <span class="badge {severity_class}">{alert.severity.value}</span>
                    </div>"""
                if adv.get("summary"):
                    html += f'<div class="item-description">{adv["summary"]}</div>'
                html += "</div>"
            html += "</div>"

        # Cost metrics
        cost_metrics = report.get_cost_metrics()
        if cost_metrics:
            total_cost = report.get_total_cost()
            html += f"""
            <div class="section">
                <h2>Cost Metrics</h2>
                <table>
                    <tr><th>Service</th><th>Period</th><th>Amount</th><th>Usage</th></tr>"""
            for cost in cost_metrics:
                if cost.amount is not None:
                    usage_display = (
                        f"{cost.usage_percent:.1f}%" if cost.usage_percent is not None else "N/A"
                    )
                    html += f"""
                    <tr>
                        <td>{cost.service}</td>
                        <td>{cost.period}</td>
                        <td>${cost.amount:.2f}</td>
                        <td>{usage_display}</td>
                    </tr>"""
            html += f"""
                    <tr style="font-weight: 600; background: #f8f9fa;">
                        <td colspan="2">Total</td>
                        <td>${total_cost:.2f}</td>
                        <td></td>
                    </tr>
                </table>
            </div>"""

        # API usage
        api_usage = []
        for check in report.checks:
            api_usage.extend(check.api_usage)

        if api_usage:
            html += """
            <div class="section">
                <h2>API Usage</h2>"""
            for usage in api_usage:
                if usage.usage_percent is not None:
                    progress_class = (
                        "danger"
                        if usage.usage_percent > 90
                        else "warning"
                        if usage.usage_percent > 70
                        else ""
                    )
                    html += f"""
                <div style="margin: 15px 0;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span><strong>{usage.service}</strong></span>
                        <span>{usage.usage_percent:.1f}%</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill {progress_class}" style="width: {usage.usage_percent}%"></div>
                    </div>"""
                    if usage.credits_remaining is not None:
                        html += f'<div class="item-meta">Remaining: {usage.credits_remaining:.0f} credits</div>'
                    html += "</div>"
            html += "</div>"

        # Check status
        html += """
            <div class="section">
                <h2>Check Status</h2>
                <table>
                    <tr><th>Check Type</th><th>Status</th><th>Issues</th></tr>"""
        for check in report.checks:
            status_icon = "✓" if check.success else "✗"
            status_color = "#388e3c" if check.success else "#d32f2f"
            issues = len(check.vulnerabilities) + len(check.findings) + len(check.errors)
            html += f"""
                    <tr>
                        <td><strong>{check.check_type.upper()}</strong></td>
                        <td style="color: {status_color}; font-weight: 600;">{status_icon} {"Success" if check.success else "Failed"}</td>
                        <td>{issues}</td>
                    </tr>"""
        html += """
                </table>
            </div>
        </div>
        
        <div class="footer">
            Generated by Guardian Security Monitoring System
        </div>
    </div>
</body>
</html>"""

        return html

    def _report_to_dict(self, report: GuardianReport) -> dict[str, Any]:
        """Convert report to dictionary for JSON serialization."""
        return {
            "generated_at": report.generated_at.isoformat(),
            "summary": report.summary,
            "checks": [
                {
                    "check_type": check.check_type,
                    "success": check.success,
                    "timestamp": check.timestamp.isoformat(),
                    "vulnerabilities_count": len(check.vulnerabilities),
                    "findings_count": len(check.findings),
                    "deployments_count": len(check.deployments),
                    "repository_alerts_count": len(check.repository_alerts),
                    "api_usage_count": len(check.api_usage),
                    "errors": check.errors,
                    "api_usage": [
                        {
                            "service": u.service,
                            "credits_total": u.credits_total,
                            "credits_used": u.credits_used,
                            "credits_remaining": u.credits_remaining,
                            "usage_percent": u.usage_percent,
                        }
                        for u in check.api_usage
                    ],
                }
                for check in report.checks
            ],
            "critical_vulnerabilities": [
                {
                    "package_name": v.package_name,
                    "package_version": v.package_version,
                    "severity": v.severity.value,
                    "summary": v.summary,
                }
                for v in report.get_critical_vulnerabilities()
            ],
            "critical_findings": [
                {
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "resource": f.resource,
                    "remediation": f.remediation,
                }
                for f in report.get_critical_findings()
            ],
            "unhealthy_deployments": [
                {
                    "platform": d.platform,
                    "project_name": d.project_name,
                    "status": d.status.value,
                    "url": d.url,
                    "error_message": d.error_message,
                }
                for d in report.get_unhealthy_deployments()
            ],
        }
