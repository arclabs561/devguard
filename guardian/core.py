"""Core guardian orchestration."""

import asyncio
import httpx


from guardian.checkers import (
    APIUsageChecker,
    AWSCostChecker,
    AWSIAMChecker,
    ContainerChecker,
    DomainChecker,
    FirecrawlChecker,
    FlyChecker,
    GitHubChecker,
    NpmChecker,
    NpmSecurityChecker,
    RedTeamChecker,
    SecretChecker,
    SwarmChecker,
    TailscaleChecker,
    TailsnitchChecker,
    TavilyChecker,
    VercelChecker,
)
from guardian.checkers.base import BaseChecker
from guardian.config import Settings
from guardian.models import GuardianReport


class Guardian:
    """Main guardian orchestrator."""

    def __init__(self, settings: Settings):
        """Initialize guardian with settings."""
        self.settings = settings
        self.checkers: list[BaseChecker] = []

        # Initialize checkers based on configuration
        if settings.npm_packages_to_monitor or settings.snyk_token:
            self.checkers.append(NpmChecker(settings))

        # Deep npm security analysis (separate from basic vulnerability checking)
        if settings.npm_security_enabled and settings.npm_packages_to_monitor:
            self.checkers.append(NpmSecurityChecker(settings))

        if settings.github_token:
            self.checkers.append(GitHubChecker(settings))

        if settings.vercel_token:
            self.checkers.append(VercelChecker(settings))

        if settings.fly_api_token:
            self.checkers.append(FlyChecker(settings))

        if settings.firecrawl_api_key:
            self.checkers.append(FirecrawlChecker(settings))

        if settings.tavily_api_key:
            self.checkers.append(TavilyChecker(settings))

        # Secret scanning (uses trufflehog - runs locally, no API needed)
        if settings.secret_scan_enabled:
            self.checkers.append(SecretChecker(settings))

        # Container/Dockerfile security checks
        if settings.container_check_enabled:
            self.checkers.append(ContainerChecker(settings))

        # AWS IAM security checks for satellite nodes
        if settings.aws_iam_check_enabled:
            self.checkers.append(AWSIAMChecker(settings))

        # AWS Cost monitoring
        if settings.aws_cost_check_enabled:
            self.checkers.append(AWSCostChecker(settings))

        # Tailscale network health
        if settings.tailscale_check_enabled:
            self.checkers.append(TailscaleChecker(settings))

        # Tailsnitch ACL security audit
        if settings.tailsnitch_check_enabled:
            self.checkers.append(TailsnitchChecker(settings))

        # Domain and SSL monitoring
        if settings.domain_check_enabled:
            self.checkers.append(DomainChecker(settings))

        # Docker Swarm health
        if settings.swarm_check_enabled:
            self.checkers.append(SwarmChecker(settings))

        # API usage/credits monitoring
        if settings.api_usage_check_enabled:
            self.checkers.append(APIUsageChecker(settings))

        # Red team testing (runs after deployment checks to test endpoints)
        if settings.redteam_enabled and (settings.vercel_token or settings.fly_api_token):
            self.checkers.append(RedTeamChecker(settings))

    def validate_configuration(self) -> list[str]:
        """
        Validate configuration and return list of warnings/errors.

        Returns:
            List of validation messages (warnings or errors)
        """
        warnings: list[str] = []

        # Check if any checkers are configured
        if not self.checkers:
            warnings.append(
                "No checkers configured. Set at least one of: "
                "npm_packages_to_monitor, github_token, vercel_token, fly_api_token"
            )

        # Check npm checker configuration
        if any(isinstance(c, NpmChecker) for c in self.checkers):
            if not self.settings.npm_packages_to_monitor and not self.settings.snyk_token:
                warnings.append(
                    "NpmChecker is enabled but no packages or Snyk token configured. "
                    "Set npm_packages_to_monitor or snyk_token."
                )

        # Check GitHub checker configuration
        if any(isinstance(c, GitHubChecker) for c in self.checkers):
            if not self.settings.github_repos_to_monitor and not self.settings.github_org:
                warnings.append(
                    "GitHubChecker is enabled but no repos or org configured. "
                    "Set github_repos_to_monitor or github_org."
                )

        # Check Vercel checker configuration
        if any(isinstance(c, VercelChecker) for c in self.checkers):
            if not self.settings.vercel_projects_to_monitor:
                warnings.append(
                    "VercelChecker is enabled but no projects configured. "
                    "Set vercel_projects_to_monitor or it will fetch all projects."
                )

        # Check Fly checker configuration
        if any(isinstance(c, FlyChecker) for c in self.checkers):
            if not self.settings.fly_apps_to_monitor:
                warnings.append(
                    "FlyChecker is enabled but no apps configured. "
                    "Set fly_apps_to_monitor or it will fetch all apps."
                )

        return warnings

    async def run_checks(self, checker_types: list[str] | None = None) -> GuardianReport:
        """Run all configured checks and generate a report.

        Args:
            checker_types: Optional list of checker types to run. If None, runs all checkers.
                          Example: ["npm", "github"] to run only npm and github checkers.
        """
        from guardian.models import CheckResult

        checks: list[CheckResult] = []
        redteam_checker = None

        # Filter checkers if specific types requested
        checkers_to_run = self.checkers
        if checker_types:
            checkers_to_run = [c for c in self.checkers if c.check_type in checker_types]

        # First pass: run all checkers except red team in parallel
        async def run_checker(checker: BaseChecker) -> CheckResult:
            """Run a single checker with proper error handling."""
            try:
                return await checker.check()
            except httpx.HTTPStatusError as e:
                return CheckResult(
                    check_type=checker.check_type,
                    success=False,
                    errors=[f"HTTP {e.response.status_code}: {e.response.text[:200]}"],
                )
            except httpx.RequestError as e:
                return CheckResult(
                    check_type=checker.check_type,
                    success=False,
                    errors=[f"Network error: {str(e)}"],
                )
            except asyncio.TimeoutError:
                return CheckResult(
                    check_type=checker.check_type,
                    success=False,
                    errors=["Check timed out"],
                )
            except Exception as e:
                # Log unexpected errors for debugging
                import logging

                logger = logging.getLogger(__name__)
                logger.error(
                    f"Unexpected error in {checker.check_type} checker: {e}", exc_info=True
                )
                return CheckResult(
                    check_type=checker.check_type,
                    success=False,
                    errors=[f"Unexpected error: {str(e)}"],
                )

        # Run checkers in parallel (except red team which needs deployment results)
        checker_tasks = []
        for checker in checkers_to_run:
            if isinstance(checker, RedTeamChecker):
                redteam_checker = checker
                continue  # Skip red team for now

            checker_tasks.append(run_checker(checker))

        # Run all checkers in parallel
        if checker_tasks:
            results = await asyncio.gather(*checker_tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    # This shouldn't happen due to error handling in run_checker, but handle it
                    import logging

                    logger = logging.getLogger(__name__)
                    logger.error(f"Checker task raised exception: {result}", exc_info=True)
                else:
                    checks.append(result)

        # Second pass: run red team checker with access to deployment results
        if redteam_checker and (not checker_types or "redteam" in checker_types):
            try:
                # Pass deployment results directly to checker
                deployment_results = [c for c in checks if c.check_type in ("vercel", "fly")]
                result = await redteam_checker.check(deployment_results=deployment_results)
                checks.append(result)
            except httpx.HTTPStatusError as e:
                checks.append(
                    CheckResult(
                        check_type="redteam",
                        success=False,
                        errors=[f"HTTP {e.response.status_code}: {e.response.text[:200]}"],
                    )
                )
            except httpx.RequestError as e:
                checks.append(
                    CheckResult(
                        check_type="redteam",
                        success=False,
                        errors=[f"Network error: {str(e)}"],
                    )
                )
            except Exception as e:
                import logging

                logger = logging.getLogger(__name__)
                logger.error(f"Red team check failed: {e}", exc_info=True)
                checks.append(
                    CheckResult(
                        check_type="redteam",
                        success=False,
                        errors=[f"Red team check failed: {str(e)}"],
                    )
                )

        # Generate summary
        report = GuardianReport(checks=checks)
        report.summary = {
            "total_checks": len(checks),
            "successful_checks": sum(1 for c in checks if c.success),
            "failed_checks": sum(1 for c in checks if not c.success),
            "total_vulnerabilities": report.get_total_vulnerabilities(),
            "critical_vulnerabilities": len(report.get_critical_vulnerabilities()),
            "total_findings": report.get_total_findings(),
            "critical_findings": len(report.get_critical_findings()),
            "unhealthy_deployments": len(report.get_unhealthy_deployments()),  # Count, not list
            "open_repository_alerts": len(report.get_open_repository_alerts()),
            "total_cost_usd": report.get_total_cost(),
        }

        # Update Prometheus metrics
        try:
            from guardian.metrics import update_metrics_from_report

            update_metrics_from_report(report)
        except ImportError:
            # Metrics not available, skip
            pass

        return report
