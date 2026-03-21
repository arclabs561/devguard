"""AWS IAM security checker for satellite nodes."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import yaml

from devguard.checkers.base import BaseChecker
from devguard.config import Settings
from devguard.models import CheckResult, Finding, Severity

logger = logging.getLogger(__name__)


def load_iam_posture(path: Path | None = None) -> dict[str, Any]:
    """Load IAM posture configuration from YAML file."""
    if path is None:
        from devguard.utils import get_iam_posture_path

        path = get_iam_posture_path()
        if path is None:
            return {}

    if path.exists():
        try:
            with open(path) as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Failed to load IAM posture config: {e}")
    return {}


class AWSIAMChecker(BaseChecker):
    """Check AWS IAM posture for satellite nodes.

    Loads configuration from ops/security/iam-posture.yaml which defines:
    - Satellite nodes and their IAM roles
    - Forbidden policy patterns
    - Security rules to enforce
    """

    check_type = "aws_iam"

    # Policies that should NEVER be attached to satellite nodes
    FORBIDDEN_POLICIES = [
        "AdministratorAccess",
        "AmazonS3FullAccess",
        "AmazonS3ReadOnlyAccess",
        "PowerUserAccess",
        "IAMFullAccess",
    ]

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.posture = load_iam_posture()
        self._init_from_posture()

    def _init_from_posture(self) -> None:
        """Initialize checker configuration from posture YAML."""
        self.satellite_nodes: dict[str, dict[str, str]] = {}

        satellites = self.posture.get("satellite_nodes", {})
        for node_name, node_config in satellites.items():
            self.satellite_nodes[node_name] = {
                "role": node_config.get("role", ""),
                "instance_id": node_config.get("instance_id", ""),
                "purpose": node_config.get("purpose", ""),
            }

        if not self.satellite_nodes:
            logger.info("No satellite nodes in posture config -- IAM check will be a no-op")

    async def check(self) -> CheckResult:
        """Check IAM roles for security issues."""
        findings: list[Finding] = []
        errors: list[str] = []
        metadata: dict[str, Any] = {
            "nodes_checked": [],
            "posture_config": bool(self.posture),
        }

        for node_name, node_config in self.satellite_nodes.items():
            role_name = node_config["role"]
            instance_id = node_config["instance_id"]

            try:
                # Get attached policies using async subprocess
                policies, error = await self._run_aws_command(
                    [
                        "aws",
                        "iam",
                        "list-attached-role-policies",
                        "--role-name",
                        role_name,
                        "--query",
                        "AttachedPolicies[].PolicyName",
                        "--output",
                        "json",
                    ]
                )

                if error:
                    findings.append(
                        Finding(
                            severity=Severity.LOW,
                            title=f"Cannot check role: {role_name}",
                            description=f"Failed to query IAM for {node_name}: {error}",
                            resource=role_name,
                            remediation="Verify AWS CLI is configured and has iam:ListAttachedRolePolicies permission",
                            metadata={"node": node_name, "instance_id": instance_id},
                        )
                    )
                    continue

                node_info = {
                    "node": node_name,
                    "role": role_name,
                    "instance_id": instance_id,
                    "policies": policies,
                }

                # Check for forbidden policies
                for policy in policies:
                    if policy in self.FORBIDDEN_POLICIES:
                        findings.append(
                            Finding(
                                severity=Severity.CRITICAL,
                                title=f"Overly broad policy on {node_name}",
                                description=(
                                    f"Role '{role_name}' has '{policy}' attached. "
                                    f"This violates least-privilege principle for satellite nodes."
                                ),
                                resource=role_name,
                                remediation=f"Replace {policy} with a scoped custom policy (see ops/security/iam-posture.yaml)",
                                metadata={
                                    "policy": policy,
                                    "node": node_name,
                                    "instance_id": instance_id,
                                },
                            )
                        )

                # Check inline policies
                inline_policies, _ = await self._run_aws_command(
                    [
                        "aws",
                        "iam",
                        "list-role-policies",
                        "--role-name",
                        role_name,
                        "--query",
                        "PolicyNames",
                        "--output",
                        "json",
                    ]
                )

                if inline_policies:
                    node_info["inline_policies"] = inline_policies

                metadata["nodes_checked"].append(node_info)

            except TimeoutError:
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        title=f"Timeout checking role: {role_name}",
                        description=f"AWS IAM query timed out for {node_name}",
                        resource=role_name,
                        remediation="Check network connectivity and AWS CLI configuration",
                        metadata={"node": node_name},
                    )
                )
            except json.JSONDecodeError as e:
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        title=f"Parse error for role: {role_name}",
                        description=f"Could not parse IAM response: {e}",
                        resource=role_name,
                        remediation="Verify AWS CLI output format",
                        metadata={"node": node_name},
                    )
                )

        # Check for credentials on nodes via SSM (if enabled)
        if self.posture:
            await self._check_node_credentials(findings, metadata)

        # success = no critical findings
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)

        return CheckResult(
            check_type=self.check_type,
            success=critical_count == 0,
            findings=findings,
            errors=errors,
            metadata=metadata,
        )

    async def _run_aws_command(
        self, cmd: list[str], timeout: float = 30.0
    ) -> tuple[list[str], str | None]:
        """Run an AWS CLI command asynchronously and return parsed JSON or error."""
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            if proc.returncode != 0:
                return [], stderr.decode().strip()

            return json.loads(stdout.decode().strip()), None

        except TimeoutError:
            if proc:
                try:
                    proc.kill()
                    await proc.wait()
                except ProcessLookupError:
                    pass
            raise
        except json.JSONDecodeError:
            raise
        except Exception as e:
            return [], str(e)

    async def _check_node_credentials(
        self, findings: list[Finding], metadata: dict[str, Any]
    ) -> None:
        """Check satellite nodes for credential files via SSM."""
        metadata["ssm_checks"] = {}

        for node_name, node_config in self.satellite_nodes.items():
            instance_id = node_config.get("instance_id")
            if not instance_id:
                continue

            try:
                # Send SSM command to check for credentials
                cmd = [
                    "aws",
                    "ssm",
                    "send-command",
                    "--instance-ids",
                    instance_id,
                    "--document-name",
                    "AWS-RunShellScript",
                    "--parameters",
                    'commands=["ls /root/.aws/credentials /home/*/.aws/credentials 2>/dev/null && echo FOUND || echo CLEAN"]',
                    "--query",
                    "Command.CommandId",
                    "--output",
                    "text",
                ]

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)

                if proc.returncode != 0:
                    # SSM not available, skip but note it
                    metadata["ssm_checks"][node_name] = "unavailable"
                    continue

                # Note: Full implementation would wait and get results
                # For now, we record that check was attempted
                metadata["ssm_checks"][node_name] = "initiated"

            except TimeoutError:
                metadata["ssm_checks"][node_name] = "timeout"
            except Exception as e:
                logger.debug(f"SSM check failed for {node_name}: {e}")
                metadata["ssm_checks"][node_name] = "error"
