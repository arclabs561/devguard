"""Vercel deployment status checker."""

import logging
from datetime import datetime

import httpx

from guardian.checkers.base import BaseChecker
from guardian.http_client import create_client, retry_with_backoff
from guardian.models import CheckResult, CheckStatus, DeploymentStatus

logger = logging.getLogger(__name__)


class VercelChecker(BaseChecker):
    """Check Vercel deployments for health status."""

    check_type = "vercel"

    async def check(self) -> CheckResult:
        """Check Vercel deployments."""
        deployments: list[DeploymentStatus] = []
        errors: list[str] = []

        if not self.settings.vercel_token:
            return CheckResult(
                check_type=self.check_type,
                success=False,
                deployments=[],
                errors=["Vercel token not configured"],
            )

        # Handle SecretStr
        vercel_token = self.settings.vercel_token
        if hasattr(vercel_token, "get_secret_value"):
            vercel_token = vercel_token.get_secret_value()

        headers = {
            "Authorization": f"Bearer {vercel_token}",
        }

        if self.settings.vercel_team_id:
            headers["x-vercel-team-id"] = self.settings.vercel_team_id

        try:
            async with create_client() as client:
                # Get list of projects
                projects = await self._get_projects(client, headers)

                # Check deployments for each project
                for project in projects:
                    try:
                        project_deployments = await self._get_project_deployments(
                            client, headers, project
                        )
                        deployments.extend(project_deployments)
                    except httpx.HTTPStatusError as e:
                        errors.append(
                            f"Error checking project {project}: "
                            f"HTTP {e.response.status_code} - {e.response.text[:100]}"
                        )
                    except httpx.RequestError as e:
                        errors.append(f"Error checking project {project}: Network error - {str(e)}")
                    except Exception as e:
                        errors.append(f"Error checking project {project}: {str(e)}")

        except httpx.RequestError as e:
            errors.append(f"Error connecting to Vercel API: {str(e)}")
        except Exception as e:
            errors.append(f"Error checking Vercel: {str(e)}")

        # Vercel doesn't have a public billing API, so we don't track costs
        return CheckResult(
            check_type=self.check_type,
            success=len(errors) == 0,
            deployments=deployments,
            errors=errors,
            cost_metrics=[],
        )

    async def _get_projects(self, client: httpx.AsyncClient, headers: dict) -> list[str]:
        """Get list of projects to monitor."""
        if self.settings.vercel_projects_to_monitor:
            return self.settings.vercel_projects_to_monitor

        # Get all projects
        try:

            async def fetch_projects():
                response = await client.get(
                    "https://api.vercel.com/v9/projects",
                    headers=headers,
                )
                response.raise_for_status()
                return response

            response = await retry_with_backoff(fetch_projects, max_retries=3)
            data = response.json()
            return [
                project.get("name", "")
                for project in data.get("projects", [])
                if project.get("name")
            ]
        except httpx.HTTPStatusError as e:
            logger.warning(f"Failed to fetch Vercel projects: HTTP {e.response.status_code}")
        except httpx.RequestError as e:
            logger.warning(f"Failed to fetch Vercel projects: {str(e)}")
        except Exception as e:
            logger.warning(f"Unexpected error fetching Vercel projects: {str(e)}")

        return []

    async def _get_project_deployments(
        self, client: httpx.AsyncClient, headers: dict, project_name: str
    ) -> list[DeploymentStatus]:
        """Get deployments for a project."""
        deployments: list[DeploymentStatus] = []

        try:

            async def fetch_deployments():
                response = await client.get(
                    "https://api.vercel.com/v6/deployments",
                    headers=headers,
                    params={"projectId": project_name, "limit": 10},
                )
                response.raise_for_status()
                return response

            response = await retry_with_backoff(fetch_deployments, max_retries=3)
            data = response.json()
            for deployment_data in data.get("deployments", []):
                deployment = self._parse_deployment(deployment_data, project_name)
                if deployment:
                    deployments.append(deployment)
        except httpx.HTTPStatusError as e:
            logger.warning(
                f"Failed to fetch deployments for {project_name}: HTTP {e.response.status_code}"
            )
        except httpx.RequestError as e:
            logger.warning(f"Network error fetching deployments for {project_name}: {str(e)}")
        except Exception as e:
            logger.warning(f"Unexpected error fetching deployments for {project_name}: {str(e)}")

        return deployments

    def _parse_deployment(
        self, deployment_data: dict, project_name: str
    ) -> DeploymentStatus | None:
        """Parse a deployment from API response."""
        try:
            # Map status
            state = deployment_data.get("state", "UNKNOWN").lower()
            status_map = {
                "ready": CheckStatus.HEALTHY,
                "building": CheckStatus.UNKNOWN,
                "error": CheckStatus.UNHEALTHY,
                "queued": CheckStatus.UNKNOWN,
                "canceled": CheckStatus.UNHEALTHY,
            }
            status = status_map.get(state, CheckStatus.UNKNOWN)

            # Parse dates
            created_at = None
            if deployment_data.get("createdAt"):
                created_at = datetime.fromtimestamp(deployment_data.get("createdAt") / 1000)

            updated_at = None
            if deployment_data.get("updatedAt"):
                updated_at = datetime.fromtimestamp(deployment_data.get("updatedAt") / 1000)

            url = deployment_data.get("url")
            if url and not url.startswith("http"):
                url = f"https://{url}"

            return DeploymentStatus(
                platform="vercel",
                project_name=project_name,
                deployment_id=deployment_data.get("uid", ""),
                status=status,
                url=url,
                created_at=created_at,
                updated_at=updated_at,
                error_message=deployment_data.get("errorMessage"),
                metadata={
                    "state": state,
                    "target": deployment_data.get("target"),
                    "type": deployment_data.get("type"),
                },
            )
        except Exception:
            return None
