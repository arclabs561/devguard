"""AWS Cost monitoring checker."""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from guardian.checkers.base import BaseChecker
from guardian.models import CheckResult, CostMetric, Finding, Severity

logger = logging.getLogger(__name__)

# Load budget config using utility module
from guardian.utils import load_budget_config


class AWSCostChecker(BaseChecker):
    """Check AWS costs against budget thresholds."""

    check_type = "aws_cost"

    # Cost thresholds - loaded from ops/config/budget.yaml if available, else use defaults
    # Defaults match ops/scripts/infra/check-cost-spend-ceiling.sh
    _budget_config = load_budget_config()
    DAILY_THRESHOLD = _budget_config.get("daily_warn", 5.0)  # Alert if daily spend exceeds this

    # Instance allowlist (from check-ec2-running-allowlist.sh)
    ALLOWED_INSTANCES = ["gyarados", "alakazam"]

    async def check(self) -> CheckResult:
        """Check AWS costs and resource compliance."""
        cost_metrics: list[CostMetric] = []
        findings: list[Finding] = []
        errors: list[str] = []
        metadata: dict = {}

        # Check MTD costs
        mtd_result = await self._get_mtd_cost()
        if mtd_result.get("error"):
            errors.append(mtd_result["error"])
        else:
            mtd_cost = mtd_result.get("cost", 0.0)
            metadata["mtd_cost"] = mtd_cost

            cost_metrics.append(
                CostMetric(
                    service="aws",
                    period="monthly",
                    amount=mtd_cost,
                )
            )

            # Check against ceiling (configurable via settings, with fallback to budget.yaml)
            budget_config = load_budget_config()
            monthly_ceiling = self.settings.aws_monthly_cost_ceiling
            # Override with budget.yaml if it exists and setting is still default
            if monthly_ceiling == 100.0 and budget_config.get("monthly_ceiling"):
                monthly_ceiling = budget_config["monthly_ceiling"]
            if mtd_cost > monthly_ceiling:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        title=f"AWS monthly ceiling exceeded: ${mtd_cost:.2f}",
                        description=f"MTD spend ${mtd_cost:.2f} exceeds ceiling ${monthly_ceiling:.2f}",
                        resource="aws-cost",
                        remediation="Review and reduce AWS resource usage immediately, or update aws_monthly_cost_ceiling if this is expected",
                    )
                )
            elif mtd_cost > monthly_ceiling * 0.8:
                findings.append(
                    Finding(
                        severity=Severity.WARNING,
                        title=f"AWS costs approaching ceiling: ${mtd_cost:.2f}",
                        description=f"MTD spend ${mtd_cost:.2f} is at {(mtd_cost / monthly_ceiling) * 100:.0f}% of ceiling ${monthly_ceiling:.2f}",
                        resource="aws-cost",
                        remediation="Monitor spending closely",
                    )
                )

        # Check yesterday's cost
        yesterday_result = await self._get_yesterday_cost()
        if yesterday_result.get("error"):
            errors.append(yesterday_result["error"])
        else:
            yesterday_cost = yesterday_result.get("cost", 0.0)
            metadata["yesterday_cost"] = yesterday_cost

            cost_metrics.append(
                CostMetric(
                    service="aws",
                    period="daily",
                    amount=yesterday_cost,
                )
            )

            if yesterday_cost > self.DAILY_THRESHOLD:
                findings.append(
                    Finding(
                        severity=Severity.WARNING,
                        title=f"High daily AWS spend: ${yesterday_cost:.2f}",
                        description=f"Yesterday's spend ${yesterday_cost:.2f} exceeds threshold ${self.DAILY_THRESHOLD:.2f}",
                        resource="aws-cost",
                        remediation="Review Cost Explorer for unexpected charges",
                    )
                )

        # Check S3-specific costs
        s3_result = await self._get_s3_costs()
        if s3_result.get("error"):
            errors.append(s3_result["error"])
        else:
            s3_cost = s3_result.get("cost", 0.0)
            metadata["s3_cost"] = s3_cost
            
            cost_metrics.append(
                CostMetric(
                    service="s3",
                    period="monthly",
                    amount=s3_cost,
                )
            )
            
            # Alert if S3 costs exceed $10/month (unusual for our usage)
            if s3_cost > 10.0:
                findings.append(
                    Finding(
                        severity=Severity.WARNING,
                        title=f"High S3 costs: ${s3_cost:.2f}/month",
                        description=f"S3 MTD cost ${s3_cost:.2f} exceeds expected threshold. Review storage usage, lifecycle policies, and request patterns.",
                        resource="s3-cost",
                        remediation="Review S3 storage classes, lifecycle policies, and list_objects_v2 call frequency",
                    )
                )

        # Check running instances against allowlist
        instances_result = await self._check_running_instances()
        if instances_result.get("error"):
            errors.append(instances_result["error"])
        else:
            running = instances_result.get("instances", [])
            metadata["running_instances"] = running

            unauthorized = [i for i in running if i not in self.ALLOWED_INSTANCES]
            if unauthorized:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        title=f"Unauthorized EC2 instances running: {unauthorized}",
                        description=f"Instances not in allowlist: {unauthorized}",
                        resource="ec2-instances",
                        remediation="Terminate unauthorized instances or add to allowlist",
                    )
                )

        return CheckResult(
            check_type=self.check_type,
            success=len(errors) == 0 and not any(f.severity == Severity.CRITICAL for f in findings),
            findings=findings,
            cost_metrics=cost_metrics,
            errors=errors,
            metadata=metadata,
        )

    async def _get_mtd_cost(self) -> dict:
        """Get month-to-date AWS cost."""
        try:
            now = datetime.now(timezone.utc)
            start_date = now.replace(day=1).strftime("%Y-%m-%d")
            end_date = now.strftime("%Y-%m-%d")

            proc = await asyncio.create_subprocess_exec(
                "aws",
                "ce",
                "get-cost-and-usage",
                "--time-period",
                f"Start={start_date},End={end_date}",
                "--granularity",
                "MONTHLY",
                "--metrics",
                "UnblendedCost",
                "--output",
                "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)

            if proc.returncode != 0:
                return {"error": f"aws ce command failed: {stderr.decode()}"}

            data = json.loads(stdout.decode())
            results = data.get("ResultsByTime", [])
            if results:
                amount = results[0].get("Total", {}).get("UnblendedCost", {}).get("Amount", "0")
                return {"cost": float(amount)}
            return {"cost": 0.0}

        except asyncio.TimeoutError:
            return {"error": "AWS CLI timeout"}
        except FileNotFoundError:
            return {"error": "aws CLI not found"}
        except Exception as e:
            return {"error": str(e)}

    async def _get_yesterday_cost(self) -> dict:
        """Get yesterday's AWS cost."""
        try:
            now = datetime.now(timezone.utc)
            yesterday = now - timedelta(days=1)
            start_date = yesterday.strftime("%Y-%m-%d")
            end_date = now.strftime("%Y-%m-%d")

            proc = await asyncio.create_subprocess_exec(
                "aws",
                "ce",
                "get-cost-and-usage",
                "--time-period",
                f"Start={start_date},End={end_date}",
                "--granularity",
                "DAILY",
                "--metrics",
                "UnblendedCost",
                "--output",
                "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)

            if proc.returncode != 0:
                return {"error": f"aws ce command failed: {stderr.decode()}"}

            data = json.loads(stdout.decode())
            results = data.get("ResultsByTime", [])
            if results:
                amount = results[0].get("Total", {}).get("UnblendedCost", {}).get("Amount", "0")
                return {"cost": float(amount)}
            return {"cost": 0.0}

        except asyncio.TimeoutError:
            return {"error": "AWS CLI timeout"}
        except FileNotFoundError:
            return {"error": "aws CLI not found"}
        except Exception as e:
            return {"error": str(e)}

    async def _get_s3_costs(self) -> dict:
        """Get S3-specific costs for current month."""
        try:
            now = datetime.now(timezone.utc)
            start_date = now.replace(day=1).strftime("%Y-%m-%d")
            end_date = now.strftime("%Y-%m-%d")

            proc = await asyncio.create_subprocess_exec(
                "aws",
                "ce",
                "get-cost-and-usage",
                "--time-period",
                f"Start={start_date},End={end_date}",
                "--granularity",
                "MONTHLY",
                "--metrics",
                "UnblendedCost",
                "--group-by",
                "Type=SERVICE",
                "--filter",
                '{"Dimensions":{"Service":["Amazon Simple Storage Service"]}}',
                "--output",
                "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)

            if proc.returncode != 0:
                return {"error": f"aws ce command failed: {stderr.decode()}"}

            data = json.loads(stdout.decode())
            results = data.get("ResultsByTime", [])
            if results:
                # Extract S3 cost from grouped results
                groups = results[0].get("Groups", [])
                for group in groups:
                    keys = group.get("Keys", [])
                    if any("Simple Storage Service" in k for k in keys):
                        amount = group.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", "0")
                        return {"cost": float(amount)}
                # If no S3 group found, cost is 0
                return {"cost": 0.0}
            return {"cost": 0.0}

        except asyncio.TimeoutError:
            return {"error": "AWS CLI timeout"}
        except FileNotFoundError:
            return {"error": "aws CLI not found"}
        except Exception as e:
            return {"error": str(e)}

    async def _check_running_instances(self) -> dict:
        """Check which EC2 instances are running."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "aws",
                "ec2",
                "describe-instances",
                "--filters",
                "Name=instance-state-name,Values=running",
                "--query",
                "Reservations[].Instances[].Tags[?Key==`Name`].Value[]",
                "--output",
                "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)

            if proc.returncode != 0:
                return {"error": f"aws ec2 command failed: {stderr.decode()}"}

            instances = json.loads(stdout.decode())
            # AWS CLI returns a flat list of instance names
            return {"instances": instances if isinstance(instances, list) else []}

        except asyncio.TimeoutError:
            return {"error": "AWS CLI timeout"}
        except FileNotFoundError:
            return {"error": "aws CLI not found"}
        except Exception as e:
            return {"error": str(e)}
