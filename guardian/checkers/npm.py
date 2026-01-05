"""npm package vulnerability checker."""

import logging
from datetime import datetime

import httpx

from guardian.checkers.base import BaseChecker
from guardian.http_client import create_client, retry_with_backoff
from guardian.models import CheckResult, Severity, Vulnerability

logger = logging.getLogger(__name__)


class NpmChecker(BaseChecker):
    """Check npm packages for vulnerabilities."""

    check_type = "npm"

    async def check(self) -> CheckResult:
        """Check npm packages for vulnerabilities."""
        vulnerabilities: list[Vulnerability] = []
        errors: list[str] = []

        if not self.settings.npm_packages_to_monitor:
            return CheckResult(
                check_type=self.check_type,
                success=True,
                vulnerabilities=[],
                errors=["No npm packages configured for monitoring"],
            )

        for package in self.settings.npm_packages_to_monitor:
            try:
                # Use npm audit for vulnerability checking
                # First, check if package.json exists or create a temporary one
                pkg_vulns = await self._check_package_vulnerabilities(package)
                vulnerabilities.extend(pkg_vulns)
            except Exception as e:
                error_msg = f"Error checking package {package}: {str(e)}"
                errors.append(error_msg)
                logger.warning(error_msg)

        # Also check for Snyk if token is available
        if self.settings.snyk_token:
            try:
                snyk_vulns = await self._check_snyk_vulnerabilities()
                vulnerabilities.extend(snyk_vulns)
            except Exception as e:
                errors.append(f"Error checking Snyk: {str(e)}")

        return CheckResult(
            check_type=self.check_type,
            success=len(errors) == 0,
            vulnerabilities=vulnerabilities,
            errors=errors,
        )

    async def _check_package_vulnerabilities(self, package: str) -> list[Vulnerability]:
        """
        Check a specific package for vulnerabilities using npm registry API.

        Uses the npm registry security advisories endpoint to check for known vulnerabilities.
        """
        vulnerabilities: list[Vulnerability] = []

        try:
            # First, get the latest version of the package
            async with create_client() as client:

                async def fetch_package_info():
                    # Get package info from npm registry
                    response = await client.get(
                        f"https://registry.npmjs.org/{package}",
                    )
                    response.raise_for_status()
                    return response

                response = await retry_with_backoff(fetch_package_info, max_retries=3)
                package_data = response.json()

                # Get latest version
                dist_tags = package_data.get("dist-tags", {})
                latest_version = dist_tags.get("latest")
                if not latest_version:
                    versions = package_data.get("versions", {})
                    if versions:
                        latest_version = max(versions.keys())

                if not latest_version:
                    logger.warning(f"Could not determine latest version for {package}")
                    return vulnerabilities

                # Check for vulnerabilities using npm audit API
                # We construct a minimal package.json structure for the audit
                audit_payload = {
                    "name": f"guardian-check-{package}",
                    "version": "1.0.0",
                    "requires": {package: latest_version},
                    "dependencies": {
                        package: {
                            "version": latest_version,
                        }
                    },
                }

                async def fetch_audit():
                    response = await client.post(
                        "https://registry.npmjs.org/-/npm/v1/security/audits",
                        json=audit_payload,
                    )
                    response.raise_for_status()
                    return response

                try:
                    audit_response = await retry_with_backoff(fetch_audit, max_retries=3)
                    audit_data = audit_response.json()

                    # Parse vulnerabilities from audit response
                    advisories = audit_data.get("advisories", {})
                    for advisory_id, advisory_data in advisories.items():
                        severity_map = {
                            "low": Severity.LOW,
                            "moderate": Severity.MEDIUM,
                            "high": Severity.HIGH,
                            "critical": Severity.CRITICAL,
                        }

                        severity = severity_map.get(
                            advisory_data.get("severity", "moderate").lower(), Severity.MEDIUM
                        )

                        # Find affected package
                        findings = advisory_data.get("findings", [])
                        for finding in findings:
                            for version_range in finding.get("version", []):
                                cves = advisory_data.get("cves", [])
                                cve_id = cves[0] if cves else None

                                created = advisory_data.get("created")
                                published_at = None
                                if created:
                                    iso_str = created.replace("Z", "+00:00")
                                    published_at = datetime.fromisoformat(iso_str)

                                vuln = Vulnerability(
                                    package_name=package,
                                    package_version=latest_version,
                                    severity=severity,
                                    advisory_id=advisory_id,
                                    cve_id=cve_id,
                                    summary=advisory_data.get("title"),
                                    description=advisory_data.get("overview"),
                                    vulnerable_version_range=version_range,
                                    published_at=published_at,
                                    source="npm",
                                )
                                vulnerabilities.append(vuln)
                                break  # Only add once per advisory
                            break

                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 404:
                        # No vulnerabilities found or endpoint not available
                        logger.debug(f"No vulnerabilities found for {package} via npm audit API")
                    else:
                        status_code = e.response.status_code
                        logger.warning(
                            f"Failed to check vulnerabilities for {package}: HTTP {status_code}"
                        )
                except httpx.RequestError as e:
                    logger.warning(
                        f"Network error checking vulnerabilities for {package}: {str(e)}"
                    )

        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code
            error_msg = f"Failed to fetch package info for {package}: HTTP {status_code}"
            logger.warning(error_msg)
            # Re-raise so caller can add to errors list
            raise Exception(error_msg) from e
        except httpx.RequestError as e:
            error_msg = f"Network error fetching package info for {package}: {str(e)}"
            logger.warning(error_msg)
            # Re-raise so caller can add to errors list
            raise Exception(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error checking {package}: {str(e)}"
            logger.warning(error_msg)
            # Re-raise so caller can add to errors list
            raise

        return vulnerabilities

    async def _check_snyk_vulnerabilities(self) -> list[Vulnerability]:
        """
        Check vulnerabilities using Snyk API.

        Note: This requires a Snyk API token and checks packages configured
        in npm_packages_to_monitor.
        """
        vulnerabilities: list[Vulnerability] = []

        if not self.settings.snyk_token:
            return vulnerabilities

        if not self.settings.npm_packages_to_monitor:
            return vulnerabilities

        # Handle SecretStr if using newer pydantic settings
        snyk_token = self.settings.snyk_token
        if hasattr(snyk_token, "get_secret_value"):
            snyk_token = snyk_token.get_secret_value()

        try:
            async with create_client() as client:
                headers = {
                    "Authorization": f"token {snyk_token}",
                    "Content-Type": "application/json",
                }

                for package in self.settings.npm_packages_to_monitor:
                    try:
                        # Get package info first to get latest version
                        async def fetch_package_info():
                            response = await client.get(
                                f"https://registry.npmjs.org/{package}",
                            )
                            response.raise_for_status()
                            return response

                        package_response = await retry_with_backoff(
                            fetch_package_info, max_retries=3
                        )
                        package_data = package_response.json()
                        dist_tags = package_data.get("dist-tags", {})
                        latest_version = dist_tags.get("latest")

                        if not latest_version:
                            continue

                        # Check vulnerabilities using Snyk API
                        # Note: Snyk API v1 endpoint for testing packages
                        async def fetch_snyk_vulns():
                            # Using Snyk's test endpoint for npm packages
                            response = await client.post(
                                "https://api.snyk.io/v1/test/npm",
                                headers=headers,
                                json={
                                    "package": {
                                        "name": package,
                                        "version": latest_version,
                                    }
                                },
                            )
                            response.raise_for_status()
                            return response

                        try:
                            snyk_response = await retry_with_backoff(
                                fetch_snyk_vulns, max_retries=3
                            )
                            snyk_data = snyk_response.json()

                            # Parse vulnerabilities from Snyk response
                            issues = snyk_data.get("issues", {}).get("vulnerabilities", [])
                            for issue in issues:
                                severity_map = {
                                    "low": Severity.LOW,
                                    "medium": Severity.MEDIUM,
                                    "high": Severity.HIGH,
                                    "critical": Severity.CRITICAL,
                                }

                                severity = severity_map.get(
                                    issue.get("severity", "medium").lower(), Severity.MEDIUM
                                )

                                identifiers = issue.get("identifiers", {})
                                cves = identifiers.get("CVE", [])
                                cve_id = cves[0] if cves else None

                                semver = issue.get("semver", {})
                                vulnerable = semver.get("vulnerable", [])
                                vulnerable_range = vulnerable[0] if vulnerable else None

                                patched = semver.get("patched", [])
                                patched_version = patched[0] if patched else None

                                pub_time = issue.get("publicationTime")
                                published_at = None
                                if pub_time:
                                    iso_str = pub_time.replace("Z", "+00:00")
                                    published_at = datetime.fromisoformat(iso_str)

                                vuln = Vulnerability(
                                    package_name=package,
                                    package_version=latest_version,
                                    severity=severity,
                                    cve_id=cve_id,
                                    summary=issue.get("title"),
                                    description=issue.get("description"),
                                    vulnerable_version_range=vulnerable_range,
                                    first_patched_version=patched_version,
                                    published_at=published_at,
                                    source="snyk",
                                )
                                vulnerabilities.append(vuln)

                        except httpx.HTTPStatusError as e:
                            if e.response.status_code == 401:
                                logger.warning("Snyk API authentication failed. Check your token.")
                            elif e.response.status_code == 404:
                                logger.debug(f"No vulnerabilities found for {package} via Snyk API")
                            else:
                                status_code = e.response.status_code
                                logger.warning(f"Snyk API error for {package}: HTTP {status_code}")
                        except httpx.RequestError as e:
                            logger.warning(f"Network error checking Snyk for {package}: {str(e)}")

                    except Exception as e:
                        logger.warning(f"Error checking {package} with Snyk: {str(e)}")

        except Exception as e:
            logger.warning(f"Unexpected error checking Snyk vulnerabilities: {str(e)}")

        return vulnerabilities
