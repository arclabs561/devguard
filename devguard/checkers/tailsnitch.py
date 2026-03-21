"""Tailsnitch security auditor for Tailscale ACLs."""

import asyncio
import json
import logging
import os
import shutil

from devguard.checkers.base import BaseChecker
from devguard.models import CheckResult, Finding, Severity

logger = logging.getLogger(__name__)


class TailsnitchChecker(BaseChecker):
    """Check Tailscale ACL security using Tailsnitch.
    
    Tailsnitch scans Tailscale ACL policies for 50+ security misconfigurations,
    overly permissive access controls, and best practice violations.
    
    Requires:
    - Tailsnitch binary installed (see https://github.com/Adversis/tailsnitch)
    - Tailscale authentication (TSKEY or OAuth credentials)
    """

    check_type = "tailsnitch"

    def __init__(self, settings):
        """Initialize Tailsnitch checker."""
        super().__init__(settings)
        # Use custom path if provided, otherwise auto-detect
        self.tailsnitch_path = (
            settings.tailsnitch_binary_path
            if settings.tailsnitch_binary_path
            else self._find_tailsnitch()
        )
        self.tailnet = settings.tailsnitch_tailnet

        # Read auth from environment (pydantic-settings loads .env automatically)
        # Support both TSKEY and TS_API_KEY for compatibility
        self.tskey = os.getenv("TSKEY") or os.getenv("TS_API_KEY")
        self.ts_oauth_client_id = os.getenv("TS_OAUTH_CLIENT_ID")
        self.ts_oauth_client_secret = os.getenv("TS_OAUTH_CLIENT_SECRET")

        logger.debug(
            "TailsnitchChecker initialized",
            extra={
                "tailsnitch_path": self.tailsnitch_path,
                "has_api_key": bool(self.tskey),
                "has_oauth": bool(self.ts_oauth_client_id and self.ts_oauth_client_secret),
                "tailnet": self.tailnet,
            },
        )

    def _find_tailsnitch(self) -> str | None:
        """Find tailsnitch binary in PATH or common locations."""
        # Check PATH first
        path = shutil.which("tailsnitch")
        if path:
            logger.debug(f"Found tailsnitch in PATH: {path}")
            return path

        # Check common install locations
        common_paths = [
            "/usr/local/bin/tailsnitch",
            "/opt/homebrew/bin/tailsnitch",
            os.path.expanduser("~/bin/tailsnitch"),
            os.path.expanduser("~/.local/bin/tailsnitch"),
        ]

        for path in common_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                logger.debug(f"Found tailsnitch at: {path}")
                return path

        logger.debug("Tailsnitch binary not found in PATH or common locations")
        return None

    async def check(self) -> CheckResult:
        """Run Tailsnitch security audit."""
        findings: list[Finding] = []
        errors: list[str] = []

        if not self.tailsnitch_path:
            install_instructions = (
                "Install Tailsnitch:\n"
                "  1. Download from https://github.com/Adversis/tailsnitch/releases\n"
                "  2. Or install via Go: go install github.com/Adversis/tailsnitch@latest\n"
                "  3. Or set TAILSNITCH_BINARY_PATH in .env to custom location"
            )
            errors.append(f"Tailsnitch binary not found. {install_instructions}")
            logger.warning("Tailsnitch binary not found", extra={"check_type": self.check_type})
            return CheckResult(
                check_type=self.check_type,
                success=False,
                errors=errors,
            )

        # Check authentication
        if not self.tskey and not (self.ts_oauth_client_id and self.ts_oauth_client_secret):
            auth_instructions = (
                "Tailscale authentication required. Set one of:\n"
                "  - TSKEY or TS_API_KEY (API key from https://login.tailscale.com/admin/settings/keys)\n"
                "  - TS_OAUTH_CLIENT_ID + TS_OAUTH_CLIENT_SECRET (OAuth from https://login.tailscale.com/admin/settings/oauth)\n"
                "Add to .env file or export as environment variables"
            )
            errors.append(auth_instructions)
            logger.warning("Tailscale authentication not configured", extra={"check_type": self.check_type})
            return CheckResult(
                check_type=self.check_type,
                success=False,
                errors=errors,
            )

        try:
            # Build command
            cmd = [self.tailsnitch_path, "--json"]

            # Add tailnet flag if specified
            if self.tailnet:
                cmd.extend(["--tailnet", self.tailnet])
                logger.debug(f"Auditing specific tailnet: {self.tailnet}")

            # Set environment variables for Tailsnitch
            env = os.environ.copy()
            if self.tskey:
                env["TSKEY"] = self.tskey
                logger.debug("Using TSKEY authentication")
            if self.ts_oauth_client_id:
                env["TS_OAUTH_CLIENT_ID"] = self.ts_oauth_client_id
                logger.debug("Using OAuth client ID")
            if self.ts_oauth_client_secret:
                env["TS_OAUTH_CLIENT_SECRET"] = self.ts_oauth_client_secret
                logger.debug("Using OAuth client secret")

            logger.info("Running Tailsnitch security audit", extra={"command": " ".join(cmd[:3])})

            # Run Tailsnitch
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)

            if proc.returncode != 0:
                stderr_text = stderr.decode() if stderr else ""
                stdout_preview = stdout.decode()[:200] if stdout else ""
                error_msg = f"Tailsnitch failed (exit {proc.returncode})"
                if stderr_text:
                    error_msg += f": {stderr_text[:500]}"
                elif stdout_preview:
                    error_msg += f": {stdout_preview}"
                errors.append(error_msg)
                logger.error(
                    "Tailsnitch execution failed",
                    extra={
                        "exit_code": proc.returncode,
                        "stderr_preview": stderr_text[:200] if stderr_text else None,
                    },
                )
                return CheckResult(
                    check_type=self.check_type,
                    success=False,
                    errors=errors,
                )

            # Parse JSON output
            try:
                output = json.loads(stdout.decode())
            except json.JSONDecodeError as e:
                errors.append(f"Failed to parse Tailsnitch JSON output: {e}")
                return CheckResult(
                    check_type=self.check_type,
                    success=False,
                    errors=errors,
                )

            # Convert Tailsnitch findings to devguard Findings
            suggestions = output.get("suggestions", [])
            summary = output.get("summary", {})
            tailnet_name = output.get("tailnet", "unknown")

            logger.info(
                "Tailsnitch audit completed",
                extra={
                    "tailnet": tailnet_name,
                    "total_checks": summary.get("total", 0),
                    "failed": summary.get("failed", 0),
                    "critical": summary.get("critical", 0),
                    "high": summary.get("high", 0),
                },
            )

            for suggestion in suggestions:
                if suggestion.get("pass", True):
                    continue  # Skip passing checks

                check_id = suggestion.get("id", "UNKNOWN")
                title = suggestion.get("title", "Unknown issue")
                severity_str = suggestion.get("severity", "info").upper()
                description = suggestion.get("description", "")
                remediation = suggestion.get("remediation", "")
                category = suggestion.get("category", "")

                # Map Tailsnitch severity to devguard severity
                severity_map = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                    "INFO": Severity.WARNING,
                }
                severity = severity_map.get(severity_str, Severity.WARNING)

                # Extract resource from suggestion (can be string, dict, or list)
                resource = suggestion.get("resource", tailnet_name)
                if isinstance(resource, dict):
                    resource = (
                        resource.get("name")
                        or resource.get("id")
                        or resource.get("hostname")
                        or tailnet_name
                    )
                elif isinstance(resource, list) and resource:
                    # If resource is a list, use first item or join
                    resource = str(resource[0]) if len(resource) == 1 else f"{tailnet_name} ({len(resource)} resources)"
                elif not resource or resource == "tailnet":
                    resource = tailnet_name

                # Build remediation with admin URL if available
                fix_info = suggestion.get("fix", {})
                admin_url = fix_info.get("admin_url")
                full_remediation = remediation
                if admin_url:
                    full_remediation = f"{remediation}\n\nFix in admin console: {admin_url}"

                findings.append(
                    Finding(
                        severity=severity,
                        title=f"{check_id}: {title}",
                        description=description,
                        resource=str(resource),
                        remediation=full_remediation,
                        metadata={
                            "check_id": check_id,
                            "category": category,
                            "tailsnitch_severity": severity_str,
                            "admin_url": admin_url,
                            "tailnet": tailnet_name,
                            "details": suggestion.get("details"),  # Additional context
                        },
                    )
                )

            # Determine overall success
            critical_count = summary.get("critical", 0)
            high_count = summary.get("high", 0)
            success = critical_count == 0 and high_count == 0

            return CheckResult(
                check_type=self.check_type,
                success=success,
                findings=findings,
                errors=errors,
                metadata={
                    "total_checks": summary.get("total", 0),
                    "passed": summary.get("passed", 0),
                    "failed": summary.get("failed", 0),
                    "critical": critical_count,
                    "high": high_count,
                    "medium": summary.get("medium", 0),
                    "low": summary.get("low", 0),
                    "info": summary.get("info", 0),
                    "tailnet": output.get("tailnet", "unknown"),
                },
            )

        except TimeoutError:
            errors.append("Tailsnitch timed out after 60s")
            return CheckResult(
                check_type=self.check_type,
                success=False,
                errors=errors,
            )
        except FileNotFoundError:
            errors.append(f"Tailsnitch binary not found at {self.tailsnitch_path}")
            return CheckResult(
                check_type=self.check_type,
                success=False,
                errors=errors,
            )
        except Exception as e:
            errors.append(f"Tailsnitch check failed: {e}")
            logger.exception("Tailsnitch check exception")
            return CheckResult(
                check_type=self.check_type,
                success=False,
                errors=errors,
            )

