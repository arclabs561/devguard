"""Tavily API usage checker."""

import logging

import httpx

from guardian.checkers.base import BaseChecker
from guardian.http_client import create_client, retry_with_backoff
from guardian.models import CheckResult, CostMetric

logger = logging.getLogger(__name__)


class TavilyChecker(BaseChecker):
    """Check Tavily API usage."""

    check_type = "tavily"

    async def check(self) -> CheckResult:
        """Check Tavily usage."""
        errors: list[str] = []

        if not self.settings.tavily_api_key:
            return CheckResult(
                check_type=self.check_type,
                success=False,
                deployments=[],
                errors=["Tavily API key not configured"],
            )

        # Handle SecretStr
        tavily_key = self.settings.tavily_api_key
        if hasattr(tavily_key, "get_secret_value"):
            tavily_key = tavily_key.get_secret_value()

        headers = {
            "Authorization": f"Bearer {tavily_key}",
        }

        try:
            async with create_client() as client:

                async def fetch_usage():
                    response = await client.get(
                        "https://api.tavily.com/usage",
                        headers=headers,
                        timeout=10.0,
                    )
                    response.raise_for_status()
                    return response

                response = await retry_with_backoff(fetch_usage, max_retries=3)
                data = response.json()

                # Extract usage data
                key_usage = data.get("key", {})
                account_usage = data.get("account", {})

                # Safely extract numeric values, defaulting to 0 if None
                key_usage_val = float(key_usage.get("usage") or 0)
                key_limit_val = float(key_usage.get("limit") or 0)
                account_usage_val = float(account_usage.get("plan_usage") or 0)
                account_limit_val = float(account_usage.get("plan_limit") or 0)

                key_usage_pct = (key_usage_val / key_limit_val * 100) if key_limit_val > 0 else 0.0
                account_usage_pct = (
                    (account_usage_val / account_limit_val * 100) if account_limit_val > 0 else 0.0
                )

                # Use the higher usage percentage
                usage_percent = max(key_usage_pct, account_usage_pct)

                metadata = {
                    "key_usage": key_usage_val,
                    "key_limit": key_limit_val,
                    "account_plan": account_usage.get("current_plan"),
                    "account_usage": account_usage_val,
                    "account_limit": account_limit_val,
                    "usage_percent": round(usage_percent, 2),
                }

                # Create cost metrics with estimated costs
                # Tavily pricing: $0.008 per credit (pay-as-you-go)
                # Free: 1000 credits/month = $0
                # Monthly plans reduce per-credit cost
                plan = account_usage.get("current_plan", "free")
                # Use $0.008 per request as standard estimate for paid plans
                cost_per_request = 0.0 if plan == "free" else 0.008

                key_cost = key_usage_val * cost_per_request if cost_per_request > 0 else None
                account_cost = (
                    account_usage_val * cost_per_request if cost_per_request > 0 else None
                )

                cost_metrics = [
                    CostMetric(
                        service="tavily",
                        period="monthly",
                        amount=key_cost,
                        usage=key_usage_val,
                        limit=key_limit_val,
                        usage_percent=round(key_usage_pct, 2),
                        metadata={
                            "unit": "requests",
                            "type": "key",
                            "cost_per_request": cost_per_request,
                            "estimated": cost_per_request > 0,
                        },
                    ),
                    CostMetric(
                        service="tavily",
                        period="monthly",
                        amount=account_cost,
                        usage=account_usage_val,
                        limit=account_limit_val,
                        usage_percent=round(account_usage_pct, 2),
                        metadata={
                            "unit": "requests",
                            "type": "account",
                            "plan": plan,
                            "cost_per_request": cost_per_request,
                            "estimated": cost_per_request > 0,
                        },
                    ),
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
            # Try to extract partial cost data from error response if available
            cost_metrics = []
            try:
                error_data = e.response.json()
                if isinstance(error_data, dict):
                    # Try to get any usage info from error response
                    key_usage = error_data.get("key", {})
                    if key_usage:
                        cost_metrics.append(
                            CostMetric(
                                service="tavily",
                                period="monthly",
                                amount=None,
                                usage=float(key_usage.get("usage") or 0),
                                limit=float(key_usage.get("limit") or 0),
                                usage_percent=0.0,
                                metadata={"error": True, "status_code": status_code},
                            )
                        )
            except Exception:
                pass
            return CheckResult(
                check_type=self.check_type,
                success=False,
                deployments=[],
                errors=errors,
                cost_metrics=cost_metrics,
            )
        except httpx.RequestError as e:
            errors.append(f"Network error: {str(e)}")
        except Exception as e:
            errors.append(f"Unexpected error: {str(e)}")

        return CheckResult(
            check_type=self.check_type,
            success=False,
            deployments=[],
            errors=errors,
            cost_metrics=[],
        )
