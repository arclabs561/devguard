"""Red team security testing for deployments."""

import logging
from datetime import datetime

import httpx

from guardian.checkers.base import BaseChecker
from guardian.http_client import create_client, retry_with_backoff
from guardian.models import CheckResult, Vulnerability, Severity

logger = logging.getLogger(__name__)


class RedTeamChecker(BaseChecker):
    """Red team security testing for deployment endpoints."""

    check_type = "redteam"

    def __init__(self, settings):
        """Initialize red team checker."""
        super().__init__(settings)
        self.endpoints_to_test: list[dict[str, str]] = []

    async def check(self, deployment_results: list | None = None) -> CheckResult:
        """Run red team security tests on endpoints.

        Args:
            deployment_results: Optional list of CheckResult objects from deployment
                               checkers (vercel, fly) to extract endpoints from.
        """
        vulnerabilities: list[Vulnerability] = []
        errors: list[str] = []

        # Reset endpoints for each check run
        self.endpoints_to_test = []

        # Collect endpoints from deployment results
        self._collect_endpoints_from_results(deployment_results or [])

        if not self.endpoints_to_test:
            return CheckResult(
                check_type=self.check_type,
                success=True,
                vulnerabilities=[],
                errors=["No endpoints to test"],
            )

        async with create_client() as client:
            for endpoint_info in self.endpoints_to_test:
                url = endpoint_info["url"]
                platform = endpoint_info.get("platform", "unknown")

                try:
                    findings = await self._test_endpoint(client, url, platform)
                    vulnerabilities.extend(findings)
                except Exception as e:
                    errors.append(f"Error testing {url}: {str(e)}")
                    logger.warning(f"Error testing endpoint {url}: {e}")

        return CheckResult(
            check_type=self.check_type,
            success=len(errors) == 0,
            vulnerabilities=vulnerabilities,
            errors=errors,
        )

    def _collect_endpoints_from_results(self, deployment_results: list) -> None:
        """Collect endpoints from deployment check results."""
        for check_result in deployment_results:
            for deployment in check_result.deployments:
                if deployment.url:
                    self.endpoints_to_test.append(
                        {
                            "url": deployment.url,
                            "platform": deployment.platform,
                            "project": deployment.project_name,
                        }
                    )

    async def _test_endpoint(
        self, client: httpx.AsyncClient, url: str, platform: str
    ) -> list[Vulnerability]:
        """Test a single endpoint for security issues."""
        findings: list[Vulnerability] = []

        # Test 1: Check for security headers
        try:
            response = await client.head(url, timeout=10.0, follow_redirects=True)
            header_issues = self._check_security_headers(response, url, platform)
            findings.extend(header_issues)
        except Exception as e:
            logger.debug(f"Error checking headers for {url}: {e}")

        # Test 2: Check for exposed admin/management endpoints
        admin_paths = [
            "/admin",
            "/api/admin",
            "/management",
            "/.env",
            "/.git",
            "/.well-known",
            "/debug",
            "/health",
            "/metrics",
            "/status",
            "/api/health",
            "/api/status",
        ]

        for path in admin_paths:
            try:
                test_url = f"{url.rstrip('/')}{path}"
                response = await client.get(test_url, timeout=5.0, follow_redirects=False)
                if response.status_code == 200:
                    # Check if it's actually exposing something
                    content_type = response.headers.get("content-type", "").lower()
                    if "json" in content_type or "text" in content_type:
                        content = response.text[:500]  # Sample first 500 chars
                        if self._is_sensitive_content(content):
                            findings.append(
                                Vulnerability(
                                    package_name=platform,
                                    package_version="",
                                    severity=Severity.HIGH,
                                    summary=f"Exposed endpoint: {path}",
                                    description=f"Endpoint {test_url} is publicly accessible and may expose sensitive information",
                                    source="redteam",
                                )
                            )
            except Exception:
                pass  # Endpoint doesn't exist or timed out

        # Test 3: Check for CORS misconfiguration
        try:
            cors_response = await client.options(
                url,
                headers={"Origin": "https://evil.com"},
                timeout=5.0,
            )
            cors_issues = self._check_cors(cors_response, url, platform)
            findings.extend(cors_issues)
        except Exception:
            pass

        # Test 4: Check for information disclosure in error messages
        try:
            # Try to trigger an error
            error_response = await client.get(
                f"{url}/nonexistent-path-{datetime.now().timestamp()}",
                timeout=5.0,
            )
            if error_response.status_code >= 400:
                error_issues = self._check_error_disclosure(error_response, url, platform)
                findings.extend(error_issues)
        except Exception:
            pass

        return findings

    def _check_security_headers(
        self, response: httpx.Response, url: str, platform: str
    ) -> list[Vulnerability]:
        """Check for missing security headers."""
        findings: list[Vulnerability] = []
        headers = response.headers

        # Required security headers
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": None,  # Any value is good
            "Content-Security-Policy": None,  # Any value is good
        }

        missing_headers = []
        for header, expected_value in security_headers.items():
            if header not in headers:
                missing_headers.append(header)
            elif expected_value and headers[header] != expected_value:
                missing_headers.append(f"{header} (incorrect value)")

        if missing_headers:
            severity = Severity.MEDIUM if len(missing_headers) <= 2 else Severity.HIGH
            findings.append(
                Vulnerability(
                    package_name=platform,
                    package_version="",
                    severity=severity,
                    summary=f"Missing security headers: {', '.join(missing_headers)}",
                    description=f"Endpoint {url} is missing important security headers",
                    source="redteam",
                )
            )

        return findings

    def _check_cors(self, response: httpx.Response, url: str, platform: str) -> list[Vulnerability]:
        """Check for CORS misconfiguration."""
        findings: list[Vulnerability] = []
        headers = response.headers

        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")

        # Check for overly permissive CORS
        if acao == "*" and acac.lower() == "true":
            findings.append(
                Vulnerability(
                    package_name=platform,
                    package_version="",
                    severity=Severity.HIGH,
                    summary="Overly permissive CORS configuration",
                    description=f"Endpoint {url} allows credentials with wildcard origin (*)",
                    source="redteam",
                )
            )
        elif acao == "*":
            findings.append(
                Vulnerability(
                    package_name=platform,
                    package_version="",
                    severity=Severity.MEDIUM,
                    summary="Permissive CORS configuration",
                    description=f"Endpoint {url} allows all origins (*)",
                    source="redteam",
                )
            )

        return findings

    def _check_error_disclosure(
        self, response: httpx.Response, url: str, platform: str
    ) -> list[Vulnerability]:
        """Check for information disclosure in error messages."""
        findings: list[Vulnerability] = []
        text = response.text.lower()

        # Sensitive patterns that shouldn't be exposed
        sensitive_patterns = [
            "stack trace",
            "exception",
            "error at",
            "file://",
            "database",
            "sql",
            "password",
            "secret",
            "api key",
            "token",
            "aws",
            "access key",
        ]

        found_patterns = [p for p in sensitive_patterns if p in text]

        if found_patterns:
            findings.append(
                Vulnerability(
                    package_name=platform,
                    package_version="",
                    severity=Severity.MEDIUM,
                    summary="Information disclosure in error messages",
                    description=f"Endpoint {url} exposes sensitive information in error responses: {', '.join(found_patterns[:3])}",
                    source="redteam",
                )
            )

        return findings

    def _is_sensitive_content(self, content: str) -> bool:
        """Check if content appears to be sensitive."""
        content_lower = content.lower()

        # Patterns indicating sensitive data
        sensitive_indicators = [
            "password",
            "secret",
            "api_key",
            "token",
            "private",
            "database",
            "connection",
            "aws",
            "access",
            "credential",
        ]

        return any(indicator in content_lower for indicator in sensitive_indicators)
