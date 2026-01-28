"""Unified API Usage/Credits checker for LLM providers."""

import asyncio
import logging
import os
from datetime import UTC, datetime
from typing import Any

import httpx

from guardian.checkers.base import BaseChecker
from guardian.models import APIUsage, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)


def _get_secret(secret) -> str | None:
    """Extract secret value from SecretStr or return string directly."""
    if secret is None:
        return None
    if hasattr(secret, "get_secret_value"):
        return secret.get_secret_value()
    return str(secret)


class APIUsageChecker(BaseChecker):
    """Check usage/credits across multiple API providers.

    Monitors:
    - Anthropic (Admin API)
    - OpenAI (Usage API)
    - OpenRouter (Credits)
    - Perplexity (undocumented)
    - Groq (undocumented)

    Alerts when:
    - Credits/balance is below threshold
    - API key is invalid or expired
    - Usage is unusually high
    """

    check_type = "api_usage"

    # Thresholds for warnings
    LOW_CREDITS_THRESHOLD_USD = 5.0
    LOW_CREDITS_PERCENT = 10  # Warn when <10% remaining

    # Budget thresholds (daily/monthly)
    DAILY_BUDGET_OPENROUTER = 5.0  # USD per day
    MONTHLY_BUDGET_OPENROUTER = 50.0  # USD per month
    BUDGET_ALERT_THRESHOLD_PCT = 80.0  # Alert when >80% of budget used

    async def check(self) -> CheckResult:
        """Check API usage across all configured providers."""
        api_usage: list[APIUsage] = []
        findings: list[Finding] = []
        errors: list[str] = []

        # Run all checks in parallel
        results = await asyncio.gather(
            self._check_openrouter(),
            self._check_anthropic(),
            self._check_openai(),
            self._check_perplexity(),
            self._check_groq(),
            return_exceptions=True,
        )

        provider_names = ["openrouter", "anthropic", "openai", "perplexity", "groq"]

        for provider, result in zip(provider_names, results):
            if isinstance(result, Exception):
                # Log all exceptions for debugging
                logger.warning(
                    f"{provider} check raised exception: {type(result).__name__}: {result}"
                )
                if not isinstance(result, (ValueError, KeyError)):
                    # Only add to errors for non-config errors
                    errors.append(f"{provider}: {result}")
                continue

            if result is None:
                logger.debug(f"{provider}: No result (key not configured or not admin key)")
                continue

            usage, provider_findings = result
            if usage:
                api_usage.append(usage)
                logger.debug(f"{provider}: Added usage data (credits_used={usage.credits_used})")
            else:
                logger.debug(f"{provider}: No usage object returned")
            findings.extend(provider_findings)

        return CheckResult(
            check_type=self.check_type,
            success=len(errors) == 0 and not any(f.severity == Severity.CRITICAL for f in findings),
            api_usage=api_usage,
            findings=findings,
            errors=errors,
            metadata={
                "providers_checked": len([u for u in api_usage]),
                "providers_with_issues": len(
                    [f for f in findings if f.severity in [Severity.HIGH, Severity.CRITICAL]]
                ),
            },
        )

    async def _check_openrouter(self) -> tuple[APIUsage | None, list[Finding]]:
        """Check OpenRouter credits."""
        api_key = _get_secret(self.settings.openrouter_api_key)
        if not api_key:
            return None, []

        findings: list[Finding] = []

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://openrouter.ai/api/v1/credits",
                    headers={"Authorization": f"Bearer {api_key}"},
                    timeout=10.0,
                )
                response.raise_for_status()
                data = response.json()

                credits_data = data.get("data", data)
                total = float(credits_data.get("total_credits", 0))
                used = float(credits_data.get("total_usage", 0))
                remaining = total - used

                usage = APIUsage(
                    service="openrouter",
                    credits_total=total,
                    credits_used=used,
                    credits_remaining=remaining,
                    usage_percent=(used / total * 100) if total > 0 else 0,
                )

                # Check for low credits
                if remaining < self.LOW_CREDITS_THRESHOLD_USD:
                    severity = Severity.HIGH if remaining > 0 else Severity.CRITICAL
                    findings.append(
                        Finding(
                            severity=severity,
                            title=f"OpenRouter credits low: ${remaining:.2f} remaining",
                            description=(
                                f"OpenRouter balance is ${remaining:.2f} "
                                f"(used ${used:.2f} of ${total:.2f}, {usage.usage_percent:.1f}% used)"
                            ),
                            resource="openrouter",
                            remediation="Add credits at https://openrouter.ai/credits",
                        )
                    )

                # Check for high usage percentage (even if credits remain)
                if usage.usage_percent > 90:
                    severity = Severity.CRITICAL if usage.usage_percent > 95 else Severity.HIGH
                    findings.append(
                        Finding(
                            severity=severity,
                            title=f"OpenRouter usage critical: {usage.usage_percent:.1f}% used",
                            description=(
                                f"OpenRouter has used {usage.usage_percent:.1f}% of purchased credits "
                                f"(${used:.2f} of ${total:.2f}). Only ${remaining:.2f} remaining."
                            ),
                            resource="openrouter",
                            remediation="Review usage patterns and add credits if needed",
                        )
                    )

                # Budget alerts (based on recent usage patterns)
                # Note: This requires tracking daily usage, which we'll get from shared tracker
                # For now, we estimate based on total usage vs time
                # TODO: Integrate with shared_usage_tracker for accurate daily/monthly tracking

                return usage, findings

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title="OpenRouter API key invalid",
                        description="The OPENROUTER_API_KEY is invalid or expired",
                        resource="openrouter",
                        remediation="Regenerate API key at https://openrouter.ai/keys",
                    )
                )
            return None, findings
        except httpx.HTTPStatusError as e:
            logger.warning(
                f"OpenRouter HTTP error: {e.response.status_code} - {e.response.text[:200]}"
            )
            return None, []
        except httpx.RequestError as e:
            logger.warning(f"OpenRouter network error: {e}")
            return None, []
        except Exception as e:
            logger.error(f"OpenRouter unexpected error: {e}", exc_info=True)
            return None, []

    async def _check_anthropic(self) -> tuple[APIUsage | None, list[Finding]]:
        """Check Anthropic usage via Admin API."""
        api_key = _get_secret(self.settings.anthropic_api_key)
        if not api_key:
            return None, []

        # Admin API requires sk-ant-admin... key
        # _get_secret already extracts the actual value, so we can check directly
        if not api_key.startswith("sk-ant-admin"):
            return None, []  # Can't check usage without admin key

        findings: list[Finding] = []

        try:
            async with httpx.AsyncClient() as client:
                # Get this month's usage
                today = datetime.now(UTC)
                start_of_month = today.replace(day=1).strftime("%Y-%m-%d")
                end_date = today.strftime("%Y-%m-%d")

                # Use the correct Usage & Cost Admin API endpoint
                # See: https://platform.claude.com/docs/en/build-with-claude/usage-cost-api
                response = await client.get(
                    "https://api.anthropic.com/v1/organizations/usage_report/messages",
                    headers={
                        "anthropic-version": "2023-06-01",
                        "x-api-key": api_key,
                    },
                    params={
                        "starting_at": f"{start_of_month}T00:00:00Z",
                        "ending_at": f"{end_date}T23:59:59Z",
                        "bucket_width": "1d",
                    },
                    timeout=30.0,
                )
                response.raise_for_status()
                data: Any = response.json()

                # Parse Usage & Cost Admin API response
                # Response structure: {"data": [{"starting_at": "...", "ending_at": "...", "results": [...]}], "has_more": bool, "next_page": str}
                total_cost = 0.0
                total_tokens = 0
                total_requests = 0

                if isinstance(data, dict):
                    buckets = data.get("data", [])
                    for bucket in buckets:
                        results = bucket.get("results", [])
                        for result in results:
                            # Each result has usage and cost data
                            usage = result.get("usage", {})
                            cost = result.get("cost", {})

                            # Aggregate tokens
                            if isinstance(usage, dict):
                                total_tokens += usage.get(
                                    "total_tokens",
                                    usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
                                )
                                total_requests += usage.get("requests", 0)

                            # Aggregate cost
                            if isinstance(cost, dict):
                                total_cost += cost.get("total", cost.get("amount", 0))
                            elif isinstance(cost, (int, float)):
                                total_cost += cost

                # If no data found, return 0 (may be no usage this month)

                usage = APIUsage(
                    service="anthropic",
                    credits_used=total_cost,
                    usage_percent=0,  # No credit system, pay-as-you-go
                    period_start=start_of_month,
                    period_end=end_date,
                    metadata={"total_tokens": total_tokens},
                )

                return usage, findings

        except httpx.HTTPStatusError as e:
            if e.response.status_code in [401, 403]:
                # Admin key might be invalid
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title="Anthropic Admin API access failed",
                        description="Could not access Anthropic Usage API - check admin key permissions",
                        resource="anthropic",
                        remediation="Ensure ANTHROPIC_API_KEY is a valid Admin API key (sk-ant-admin...)",
                    )
                )
            return None, findings
        except httpx.HTTPStatusError as e:
            if e.response.status_code in [401, 403]:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title="Anthropic Admin API access failed",
                        description=f"HTTP {e.response.status_code}: {e.response.text[:200]}",
                        resource="anthropic",
                        remediation="Ensure ANTHROPIC_API_KEY is a valid Admin API key (sk-ant-admin...)",
                    )
                )
            else:
                logger.warning(
                    f"Anthropic HTTP error: {e.response.status_code} - {e.response.text[:200]}"
                )
            return None, findings
        except httpx.RequestError as e:
            logger.warning(f"Anthropic network error: {e}")
            return None, []
        except Exception as e:
            logger.error(f"Anthropic unexpected error: {e}", exc_info=True)
            return None, []

    async def _check_openai(self) -> tuple[APIUsage | None, list[Finding]]:
        """Check OpenAI usage via Usage API."""
        api_key = _get_secret(self.settings.openai_api_key)
        if not api_key:
            return None, []

        findings: list[Finding] = []

        try:
            async with httpx.AsyncClient() as client:
                today = datetime.now(UTC)
                start_of_month = today.replace(day=1).strftime("%Y-%m-%d")

                # Try the usage endpoint - OpenAI requires organization header for some endpoints
                headers = {"Authorization": f"Bearer {api_key}"}

                # Try with organization header if available
                org_id = os.getenv("OPENAI_ORG_ID")
                if org_id:
                    headers["OpenAI-Organization"] = org_id

                response = await client.get(
                    "https://api.openai.com/v1/usage",
                    headers=headers,
                    params={
                        "start_date": start_of_month,
                        "end_date": today.strftime("%Y-%m-%d"),
                    },
                    timeout=30.0,
                )

                # If that fails, try the organization endpoint
                if response.status_code != 200:
                    response = await client.get(
                        "https://api.openai.com/v1/organization/usage",
                        headers=headers,
                        params={
                            "start_time": f"{start_of_month}T00:00:00Z",
                            "end_time": f"{today.strftime('%Y-%m-%d')}T23:59:59Z",
                            "interval": "1d",
                        },
                        timeout=30.0,
                    )

                if response.status_code == 200:
                    data = response.json()
                    usage_data = data.get("data", [])

                    total_tokens = sum(
                        entry.get("input_tokens", 0) + entry.get("output_tokens", 0)
                        for entry in usage_data
                    )

                    # Try to get costs
                    cost_response = await client.get(
                        "https://api.openai.com/v1/organization/costs",
                        headers={"Authorization": f"Bearer {api_key}"},
                        params={
                            "start_time": f"{start_of_month}T00:00:00Z",
                            "end_time": f"{today.strftime('%Y-%m-%d')}T23:59:59Z",
                            "interval": "1d",
                        },
                        timeout=30.0,
                    )

                    total_cost = 0.0
                    if cost_response.status_code == 200:
                        cost_data = cost_response.json()
                        results = cost_data.get("data", {}).get("results", [])
                        for bucket in results:
                            total_cost += bucket.get("amount", {}).get("value", 0)

                    usage = APIUsage(
                        service="openai",
                        credits_used=total_cost,
                        usage_percent=0,
                        period_start=start_of_month,
                        period_end=today.strftime("%Y-%m-%d"),
                        metadata={"total_tokens": total_tokens},
                    )

                    return usage, findings
                else:
                    # API key might not have usage permissions
                    return None, []

        except httpx.HTTPStatusError as e:
            if e.response.status_code in [401, 403]:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title="OpenAI Usage API access failed",
                        description="Could not access OpenAI Usage API - check API key permissions",
                        resource="openai",
                        remediation="Ensure OPENAI_API_KEY has 'api.usage.read' scope",
                    )
                )
            return None, findings
        except Exception as e:
            logger.debug(f"OpenAI check failed: {e}")
            return None, []

    async def _check_perplexity(self) -> tuple[APIUsage | None, list[Finding]]:
        """Check Perplexity API (undocumented - just validate key)."""
        api_key = _get_secret(self.settings.perplexity_api_key)
        if not api_key:
            return None, []

        findings: list[Finding] = []

        try:
            async with httpx.AsyncClient() as client:
                # Perplexity doesn't have a public usage API, just validate key works
                # Try the correct endpoint
                response = await client.get(
                    "https://api.perplexity.ai/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                    timeout=10.0,
                )

                # If that fails, try chat completions endpoint
                if response.status_code != 200:
                    response = await client.post(
                        "https://api.perplexity.ai/chat/completions",
                        headers={
                            "Authorization": f"Bearer {api_key}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": "llama-3.1-sonar-small-128k-online",
                            "messages": [{"role": "user", "content": "test"}],
                        },
                        timeout=10.0,
                    )

                if response.status_code == 200:
                    usage = APIUsage(
                        service="perplexity",
                        credits_remaining=-1,  # Unknown
                        usage_percent=0,
                        metadata={"status": "key_valid"},
                    )
                    return usage, findings
                elif response.status_code == 401:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title="Perplexity API key invalid",
                            description="The PERPLEXITY_API_KEY is invalid or expired",
                            resource="perplexity",
                            remediation="Regenerate API key at https://www.perplexity.ai/settings/api",
                        )
                    )
                    return None, findings

        except Exception as e:
            logger.debug(f"Perplexity check failed: {e}")

        return None, []

    async def _check_groq(self) -> tuple[APIUsage | None, list[Finding]]:
        """Check Groq API (validate key, no usage API)."""
        api_key = _get_secret(self.settings.groq_api_key)
        if not api_key:
            return None, []

        findings: list[Finding] = []

        try:
            async with httpx.AsyncClient() as client:
                # Groq doesn't have a public usage API, just validate key works
                response = await client.get(
                    "https://api.groq.com/openai/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                    timeout=10.0,
                )

                if response.status_code == 200:
                    usage = APIUsage(
                        service="groq",
                        credits_remaining=-1,  # Unknown (free tier)
                        usage_percent=0,
                        metadata={"status": "key_valid"},
                    )
                    return usage, findings
                elif response.status_code == 401:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title="Groq API key invalid",
                            description="The GROQ_API_KEY is invalid or expired",
                            resource="groq",
                            remediation="Regenerate API key at https://console.groq.com/keys",
                        )
                    )
                    return None, findings

        except httpx.HTTPStatusError as e:
            logger.warning(f"Groq HTTP error: {e.response.status_code} - {e.response.text[:200]}")
            return None, []
        except httpx.RequestError as e:
            logger.warning(f"Groq network error: {e}")
            return None, []
        except Exception as e:
            logger.error(f"Groq unexpected error: {e}", exc_info=True)
            return None, []
