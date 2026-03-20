"""Fly.io deployment status checker."""

import logging

import httpx

from devguard.checkers.base import BaseChecker
from devguard.http_client import create_client, retry_with_backoff
from devguard.models import CheckResult, CheckStatus, DeploymentStatus

logger = logging.getLogger(__name__)


class FlyChecker(BaseChecker):
    """Check Fly.io deployments for health status."""

    check_type = "fly"

    async def check(self) -> CheckResult:
        """Check Fly.io deployments."""
        deployments: list[DeploymentStatus] = []
        errors: list[str] = []

        if not self.settings.fly_api_token:
            return CheckResult(
                check_type=self.check_type,
                success=False,
                deployments=[],
                errors=["Fly.io API token not configured"],
            )

        # Handle SecretStr
        fly_token = self.settings.fly_api_token
        if hasattr(fly_token, "get_secret_value"):
            fly_token = fly_token.get_secret_value()

        headers = {
            "Authorization": f"Bearer {fly_token}",
        }

        try:
            async with create_client() as client:
                # Get list of apps
                apps = await self._get_apps(client, headers)

                # Check status for each app
                for app in apps:
                    try:
                        app_deployments = await self._get_app_status(client, headers, app)
                        deployments.extend(app_deployments)
                    except httpx.HTTPStatusError as e:
                        status_code = e.response.status_code
                        error_text = e.response.text[:100]
                        errors.append(
                            f"Error checking app {app}: HTTP {status_code} - {error_text}"
                        )
                    except httpx.RequestError as e:
                        errors.append(f"Error checking app {app}: Network error - {str(e)}")
                    except Exception as e:
                        errors.append(f"Error checking app {app}: {str(e)}")

        except httpx.RequestError as e:
            errors.append(f"Error connecting to Fly.io API: {str(e)}")
        except Exception as e:
            errors.append(f"Error checking Fly.io: {str(e)}")

        return CheckResult(
            check_type=self.check_type,
            success=len(errors) == 0,
            deployments=deployments,
            errors=errors,
        )

    async def _get_apps(self, client: httpx.AsyncClient, headers: dict) -> list[str]:
        """Get list of apps to monitor."""
        if self.settings.fly_apps_to_monitor:
            return self.settings.fly_apps_to_monitor

        # Get all apps
        try:

            async def fetch_apps():
                response = await client.get(
                    "https://api.machines.dev/v1/apps",
                    headers=headers,
                )
                response.raise_for_status()
                return response

            response = await retry_with_backoff(fetch_apps, max_retries=3)
            data = response.json()
            return [app.get("name", "") for app in data if app.get("name")]
        except httpx.HTTPStatusError as e:
            logger.warning(f"Failed to fetch Fly.io apps: HTTP {e.response.status_code}")
        except httpx.RequestError as e:
            logger.warning(f"Failed to fetch Fly.io apps: {str(e)}")
        except Exception as e:
            logger.warning(f"Unexpected error fetching Fly.io apps: {str(e)}")

        return []

    async def _get_app_status(
        self, client: httpx.AsyncClient, headers: dict, app_name: str
    ) -> list[DeploymentStatus]:
        """Get status for a Fly.io app."""
        deployments: list[DeploymentStatus] = []

        try:
            # Get app status with retry
            async def fetch_app():
                response = await client.get(
                    f"https://api.machines.dev/v1/apps/{app_name}",
                    headers=headers,
                )
                response.raise_for_status()
                return response

            response = await retry_with_backoff(fetch_app, max_retries=3)
            app_data = response.json()

            # Get machines/instances with retry
            async def fetch_machines():
                response = await client.get(
                    f"https://api.machines.dev/v1/apps/{app_name}/machines",
                    headers=headers,
                )
                response.raise_for_status()
                return response

            machines = []
            try:
                machines_response = await retry_with_backoff(fetch_machines, max_retries=3)
                machines_data = machines_response.json()
                # API returns a list directly, not a dict with "machines" key
                if isinstance(machines_data, list):
                    machines = machines_data
                else:
                    machines = machines_data.get("machines", [])
            except httpx.RequestError as e:
                logger.warning(f"Failed to fetch machines for {app_name}: {str(e)}")

            # Determine overall health based on machine states
            status = CheckStatus.HEALTHY
            status_reason = None

            if not machines:
                # App exists but has no machines - likely suspended or scaled to zero
                # Check if app is explicitly suspended
                app_state = app_data.get("state", "").lower()
                if app_state == "suspended":
                    status = CheckStatus.UNKNOWN
                    status_reason = "App is suspended (intentional)"
                else:
                    status = CheckStatus.UNKNOWN
                    status_reason = "No machines running (suspended or scaled to zero)"
            else:
                # Check machine states
                running_count = 0
                stopped_count = 0
                failed_count = 0

                for machine in machines:
                    machine_state = machine.get("state", "").lower()
                    if machine_state in ["started", "running"]:
                        running_count += 1
                    elif machine_state in ["stopped", "suspended"]:
                        stopped_count += 1
                    elif machine_state in ["destroyed", "failed"]:
                        failed_count += 1

                if failed_count > 0:
                    status = CheckStatus.UNHEALTHY
                    status_reason = f"{failed_count} machine(s) failed"
                elif running_count == 0 and stopped_count > 0:
                    status = CheckStatus.UNKNOWN
                    status_reason = f"All {stopped_count} machine(s) stopped"
                elif running_count > 0:
                    status = CheckStatus.HEALTHY
                    status_reason = f"{running_count} machine(s) running"

            # Get latest deployment
            latest_deployment = None
            if machines:
                # Find the most recent machine
                latest_machine = max(
                    machines,
                    key=lambda m: m.get("created_at", ""),
                    default=None,
                )
                if latest_machine:
                    latest_deployment = latest_machine.get("id")

            url = app_data.get("hostname")
            if not url:
                # Fallback to standard Fly.io domain if hostname is missing
                url = f"{app_name}.fly.dev"

            if url and not url.startswith("http"):
                url = f"https://{url}"

            deployment = DeploymentStatus(
                platform="fly",
                project_name=app_name,
                deployment_id=latest_deployment or app_name,
                status=status,
                url=url,
                metadata={
                    "machines_count": len(machines),
                    "app_id": app_data.get("id"),
                    "status_reason": status_reason,
                },
            )

            deployments.append(deployment)

        except httpx.HTTPStatusError as e:
            logger.warning(
                f"Failed to get status for Fly.io app {app_name}: HTTP {e.response.status_code}"
            )
        except httpx.RequestError as e:
            logger.warning(f"Network error checking Fly.io app {app_name}: {str(e)}")
        except Exception as e:
            logger.warning(f"Unexpected error checking Fly.io app {app_name}: {str(e)}")

        return deployments
