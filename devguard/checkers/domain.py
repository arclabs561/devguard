"""Domain and SSL certificate checker."""

import asyncio
import logging
import socket
import ssl
from datetime import UTC, datetime

import httpx

from devguard.checkers.base import BaseChecker
from devguard.models import CheckResult, CheckStatus, DeploymentStatus, Finding, Severity

logger = logging.getLogger(__name__)


class DomainChecker(BaseChecker):
    """Check domain health and SSL certificate expiry."""

    check_type = "domain"

    # SSL warning thresholds (days)
    SSL_CRITICAL_DAYS = 7
    SSL_WARNING_DAYS = 30

    async def check(self) -> CheckResult:
        """Check all domains for health and SSL status."""
        deployments: list[DeploymentStatus] = []
        findings: list[Finding] = []
        errors: list[str] = []

        domains = self.settings.domains_to_monitor
        if not domains:
            return CheckResult(
                check_type=self.check_type,
                success=True,
                metadata={"skipped": "no domains configured (set DOMAINS_TO_MONITOR)"},
            )

        for domain in domains:
            try:
                # Check SSL certificate
                ssl_info = await self._check_ssl(domain)

                if ssl_info.get("error"):
                    status = CheckStatus.UNHEALTHY
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title=f"SSL check failed: {domain}",
                            description=ssl_info["error"],
                            resource=domain,
                            remediation="Check domain DNS and certificate configuration",
                        )
                    )
                else:
                    days_until_expiry = ssl_info.get("days_until_expiry", 0)

                    if days_until_expiry <= self.SSL_CRITICAL_DAYS:
                        status = CheckStatus.UNHEALTHY
                        findings.append(
                            Finding(
                                severity=Severity.CRITICAL,
                                title=f"SSL certificate expiring soon: {domain}",
                                description=f"Certificate expires in {days_until_expiry} days",
                                resource=domain,
                                remediation="Renew SSL certificate immediately",
                            )
                        )
                    elif days_until_expiry <= self.SSL_WARNING_DAYS:
                        status = CheckStatus.HEALTHY
                        findings.append(
                            Finding(
                                severity=Severity.WARNING,
                                title=f"SSL certificate expiring: {domain}",
                                description=f"Certificate expires in {days_until_expiry} days",
                                resource=domain,
                                remediation="Plan SSL certificate renewal",
                            )
                        )
                    else:
                        status = CheckStatus.HEALTHY

                deployments.append(
                    DeploymentStatus(
                        platform="domain",
                        project_name=domain,
                        deployment_id=domain,
                        status=status,
                        url=f"https://{domain}",
                        metadata={
                            "ssl_valid": not ssl_info.get("error"),
                            "ssl_expiry": ssl_info.get("expiry"),
                            "ssl_days_remaining": ssl_info.get("days_until_expiry"),
                            "ssl_issuer": ssl_info.get("issuer"),
                        },
                    )
                )

            except httpx.HTTPStatusError as e:
                errors.append(
                    f"HTTP {e.response.status_code} checking {domain}: {e.response.text[:200]}"
                )
            except httpx.RequestError as e:
                errors.append(f"Network error checking {domain}: {e}")
            except TimeoutError:
                errors.append(f"Timeout checking {domain}")
            except Exception as e:
                errors.append(f"Unexpected error checking {domain}: {e}")

        all_healthy = all(d.status == CheckStatus.HEALTHY for d in deployments)

        return CheckResult(
            check_type=self.check_type,
            success=len(errors) == 0 and all_healthy,
            deployments=deployments,
            findings=findings,
            errors=errors,
        )

    async def _check_ssl(self, domain: str) -> dict:
        """Check SSL certificate for a domain."""
        try:
            # Run in thread pool since ssl is blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._get_ssl_info, domain)
        except Exception as e:
            return {"error": str(e)}

    def _get_ssl_info(self, domain: str) -> dict:
        """Get SSL certificate information (blocking)."""
        try:
            # First check DNS resolution
            try:
                socket.gethostbyname(domain)
            except socket.gaierror as e:
                return {"error": f"DNS resolution failed for {domain}: {e}"}

            # Try SSL connection
            context = ssl.create_default_context()
            # Allow more lenient SSL for checking (we're just checking expiry, not validating trust)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    # Parse expiry date
                    expiry_str = cert.get("notAfter", "")
                    # Format: 'Dec 25 23:59:59 2025 GMT'
                    expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                    expiry = expiry.replace(tzinfo=UTC)

                    now = datetime.now(UTC)
                    days_until_expiry = (expiry - now).days

                    # Get issuer
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    issuer = issuer_dict.get("organizationName", "Unknown")

                    return {
                        "expiry": expiry.isoformat(),
                        "days_until_expiry": days_until_expiry,
                        "issuer": issuer,
                    }
        except TimeoutError:
            return {
                "error": f"Connection timeout to {domain}:443 - domain may be down or behind firewall"
            }
        except socket.gaierror as e:
            return {"error": f"DNS resolution failed for {domain}: {e}"}
        except ssl.SSLError as e:
            # More specific SSL error messages
            error_msg = str(e)
            if "certificate verify failed" in error_msg.lower():
                return {"error": f"SSL certificate verification failed for {domain}: {e}"}
            elif "handshake" in error_msg.lower():
                return {"error": f"SSL handshake failed for {domain}: {e}"}
            else:
                return {"error": f"SSL error for {domain}: {e}"}
        except ConnectionRefusedError:
            return {"error": f"Connection refused to {domain}:443 - service may be down"}
        except OSError as e:
            if "Network is unreachable" in str(e):
                return {"error": f"Network unreachable for {domain}: {e}"}
            return {"error": f"Connection error for {domain}: {e}"}
        except Exception as e:
            return {"error": f"Failed to check {domain}: {e}"}
