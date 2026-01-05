"""Firecrawl API usage checker."""

import logging

import httpx

from guardian.checkers.base import BaseChecker
from guardian.http_client import create_client, retry_with_backoff
from guardian.models import CheckResult, CostMetric

logger = logging.getLogger(__name__)


class FirecrawlChecker(BaseChecker):
    """Check Firecrawl API credit usage."""

    check_type = "firecrawl"

    async def check(self) -> CheckResult:
        """Check Firecrawl credit usage."""
        errors: list[str] = []

        if not self.settings.firecrawl_api_key:
            return CheckResult(
                check_type=self.check_type,
                success=False,
                deployments=[],
                errors=["Firecrawl API key not configured"],
            )

        # Handle SecretStr
        firecrawl_key = self.settings.firecrawl_api_key
        if hasattr(firecrawl_key, "get_secret_value"):
            firecrawl_key = firecrawl_key.get_secret_value()

        headers = {
            "Authorization": f"Bearer {firecrawl_key}",
        }

        try:
            async with create_client() as client:

                async def fetch_usage():
                    response = await client.get(
                        "https://api.firecrawl.dev/v2/team/credit-usage",
                        headers=headers,
                        timeout=10.0,
                    )
                    response.raise_for_status()
                    return response

                response = await retry_with_backoff(fetch_usage, max_retries=3)
                data = response.json()

                # Extract usage data
                usage_data = data.get("data", {})
                remaining = usage_data.get("remaining_credits", 0)
                plan_credits = usage_data.get("plan_credits", 0)
                usage_percent = (
                    ((plan_credits - remaining) / plan_credits * 100) if plan_credits > 0 else 0
                )

                metadata = {
                    "remaining_credits": remaining,
                    "plan_credits": plan_credits,
                    "usage_percent": round(usage_percent, 2),
                    "billing_period_start": usage_data.get("billing_period_start"),
                    "billing_period_end": usage_data.get("billing_period_end"),
                }

                # Create cost metric with estimated cost
                # Firecrawl pricing: $0.005 per credit (standard plan)
                # Hobby: $16/3000 = $0.0053, Standard: $83/100k = $0.00083
                # Use $0.005 as standard estimate
                credits_used = plan_credits - remaining
                estimated_cost = max(0.0, credits_used * 0.005) if credits_used > 0 else 0.0

                cost_metrics = [
                    CostMetric(
                        service="firecrawl",
                        period="billing_period",
                        amount=estimated_cost,
                        usage=float(credits_used),
                        limit=float(plan_credits),
                        usage_percent=round(usage_percent, 2),
                        metadata={
                            "unit": "credits",
                            "cost_per_credit": 0.005,
                            "estimated": True,
                        },
                    )
                ]

                return CheckResult(
                    check_type=self.check_type,
                    success=True,
                    deployments=[],
                    errors=[],
                    cost_metrics=cost_metrics,
                    metadata=metadata,
                )

        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code
            error_text = e.response.text[:100]
            errors.append(f"HTTP {status_code}: {error_text}")
        except httpx.RequestError as e:
            errors.append(f"Network error: {str(e)}")
        except Exception as e:
            errors.append(f"Unexpected error: {str(e)}")

        return CheckResult(
            check_type=self.check_type,
            success=False,
            deployments=[],
            errors=errors,
        )
