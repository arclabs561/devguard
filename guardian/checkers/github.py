"""GitHub repository security alerts checker."""

import logging
from datetime import datetime

import httpx
from github import Auth, Github
from github.GithubException import GithubException

from guardian.checkers.base import BaseChecker
from guardian.config import Settings
from guardian.http_client import create_client, retry_with_backoff
from guardian.models import CheckResult, RepositoryAlert, Severity

logger = logging.getLogger(__name__)


class GitHubChecker(BaseChecker):
    """Check GitHub repositories for security alerts."""

    check_type = "gh"

    def __init__(self, settings: Settings):
        """Initialize GitHub checker."""
        super().__init__(settings)
        # Handle SecretStr if using newer pydantic settings
        token = settings.github_token
        if hasattr(token, "get_secret_value"):
            token = token.get_secret_value()

        auth = Auth.Token(token)
        self.github = Github(auth=auth)

    async def check(self) -> CheckResult:
        """Check GitHub repositories for Dependabot alerts."""
        alerts: list[RepositoryAlert] = []
        errors: list[str] = []

        # Skip if no repos or org explicitly configured
        if not self.settings.github_repos_to_monitor and not self.settings.github_org:
            return CheckResult(
                check_type=self.check_type,
                success=True,
                repository_alerts=[],
                errors=[],
            )

        try:
            # Get repositories to check
            repos = await self._get_repositories()

            for repo in repos:
                try:
                    repo_alerts = await self._get_dependabot_alerts(repo)
                    alerts.extend(repo_alerts)
                except GithubException as e:
                    errors.append(f"Error checking repo {repo.full_name}: {str(e)}")
                except Exception as e:
                    errors.append(f"Unexpected error checking repo {repo.full_name}: {str(e)}")

        except Exception as e:
            errors.append(f"Error getting repositories: {str(e)}")
            return CheckResult(
                check_type=self.check_type,
                success=False,
                repository_alerts=[],
                errors=errors,
            )

        return CheckResult(
            check_type=self.check_type,
            success=len(errors) == 0,
            repository_alerts=alerts,
            errors=errors,
        )

    async def _get_repositories(self) -> list:
        """Get list of repositories to monitor."""
        repos = []

        if self.settings.github_org:
            # Get all repos in organization
            try:
                org = self.github.get_organization(self.settings.github_org)
                repos.extend(list(org.get_repos()))
            except GithubException as e:
                org_name = self.settings.github_org
                raise Exception(f"Error accessing organization {org_name}: {str(e)}")

        # Add specific repos if configured
        if self.settings.github_repos_to_monitor:
            for repo_name in self.settings.github_repos_to_monitor:
                try:
                    repo = self.github.get_repo(repo_name)
                    if repo not in repos:
                        repos.append(repo)
                except GithubException:
                    # Repo might not exist or not accessible
                    pass

        # If no specific repos configured, get user's repos
        if not repos:
            try:
                user = self.github.get_user()
                repos.extend(list(user.get_repos()))
            except GithubException:
                pass

        return repos

    async def _get_dependabot_alerts(self, repo) -> list[RepositoryAlert]:
        """Get Dependabot alerts for a repository."""
        alerts: list[RepositoryAlert] = []

        try:
            # Use GitHub API to get Dependabot alerts
            # Note: This requires the repository to have Dependabot enabled
            # and the token to have security_events scope
            # Using REST API directly as PyGithub doesn't fully support Dependabot alerts
            headers = {
                "Accept": "application/vnd.github+json",
                "Authorization": f"token {self.settings.github_token}",
                "X-GitHub-Api-Version": "2022-11-28",
            }

            async with create_client() as client:

                async def fetch_alerts():
                    response = await client.get(
                        f"https://api.github.com/repos/{repo.full_name}/dependabot/alerts",
                        headers=headers,
                    )
                    response.raise_for_status()
                    return response

                try:
                    response = await retry_with_backoff(fetch_alerts, max_retries=3)
                    data = response.json()
                    for alert_data in data:
                        alert = self._parse_alert(alert_data, repo.full_name)
                        if alert:
                            alerts.append(alert)
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 404:
                        # Dependabot might not be enabled for this repo
                        logger.debug(f"Dependabot not enabled for {repo.full_name}")
                    else:
                        logger.warning(
                            f"Failed to fetch Dependabot alerts for {repo.full_name}: "
                            f"HTTP {e.response.status_code}"
                        )
                except httpx.RequestError as e:
                    logger.warning(
                        f"Network error fetching Dependabot alerts for {repo.full_name}: {str(e)}"
                    )

        except Exception as e:
            # If we can't get alerts, continue
            logger.warning(f"Unexpected error fetching alerts for {repo.full_name}: {str(e)}")

        return alerts

    def _parse_alert(self, alert_data: dict, repo_name: str) -> RepositoryAlert | None:
        """Parse a Dependabot alert from API response."""
        try:
            # Map severity
            severity_str = alert_data.get("security_advisory", {}).get("severity", "low")
            severity_map = {
                "low": Severity.LOW,
                "medium": Severity.MEDIUM,
                "moderate": Severity.MEDIUM,
                "high": Severity.HIGH,
                "critical": Severity.CRITICAL,
            }
            severity = severity_map.get(severity_str.lower(), Severity.LOW)

            # Parse dates
            created_at = datetime.fromisoformat(
                alert_data.get("created_at", "").replace("Z", "+00:00")
            )
            updated_at = datetime.fromisoformat(
                alert_data.get("updated_at", "").replace("Z", "+00:00")
            )

            dismissed_at = None
            if alert_data.get("dismissed_at"):
                dismissed_at = datetime.fromisoformat(
                    alert_data.get("dismissed_at", "").replace("Z", "+00:00")
                )

            fixed_at = None
            if alert_data.get("fixed_at"):
                fixed_at = datetime.fromisoformat(
                    alert_data.get("fixed_at", "").replace("Z", "+00:00")
                )

            return RepositoryAlert(
                repository=repo_name,
                alert_id=alert_data.get("number", 0),
                state=alert_data.get("state", "open"),
                severity=severity,
                dependency=alert_data.get("dependency", {}),
                security_advisory=alert_data.get("security_advisory", {}),
                created_at=created_at,
                updated_at=updated_at,
                dismissed_at=dismissed_at,
                fixed_at=fixed_at,
            )
        except Exception:
            return None
