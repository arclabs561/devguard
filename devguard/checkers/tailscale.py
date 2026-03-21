"""Tailscale node health checker."""

import asyncio
import json
import logging

from devguard.checkers.base import BaseChecker
from devguard.models import CheckResult, CheckStatus, DeploymentStatus, Finding, Severity

logger = logging.getLogger(__name__)


class TailscaleChecker(BaseChecker):
    """Check Tailscale mesh network health."""

    check_type = "tailscale"

    async def check(self) -> CheckResult:
        """Check Tailscale node status."""
        deployments: list[DeploymentStatus] = []
        findings: list[Finding] = []
        errors: list[str] = []

        expected_nodes = set(self.settings.tailscale_expected_nodes)

        try:
            # Run tailscale status --json
            proc = await asyncio.create_subprocess_exec(
                "tailscale",
                "status",
                "--json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)

            if proc.returncode != 0:
                errors.append(f"tailscale status failed: {stderr.decode()}")
                return CheckResult(
                    check_type=self.check_type,
                    success=False,
                    errors=errors,
                )

            status = json.loads(stdout.decode())
            peers = status.get("Peer", {})
            self_node = status.get("Self", {})

            # Check self node
            if self_node:
                self_name = self_node.get("HostName", "unknown")
                deployments.append(
                    DeploymentStatus(
                        platform="tailscale",
                        project_name=self_name,
                        deployment_id=self_node.get("PublicKey", "")[:16],
                        status=CheckStatus.HEALTHY,
                        url=f"tailscale://{self_name}",
                        metadata={"role": "self", "online": True},
                    )
                )

            # Check all peers
            seen_nodes = {self_node.get("HostName", "")}
            for pubkey, peer in peers.items():
                hostname = peer.get("HostName", "unknown")
                seen_nodes.add(hostname)
                online = peer.get("Online", False)

                is_expected = hostname in expected_nodes

                if online:
                    status_val = CheckStatus.HEALTHY
                elif is_expected:
                    status_val = CheckStatus.UNHEALTHY
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title=f"Expected node offline: {hostname}",
                            description=f"{hostname} is offline but listed in expected nodes",
                            resource=hostname,
                            remediation=f"Check {hostname} connectivity",
                        )
                    )
                else:
                    status_val = CheckStatus.UNKNOWN

                deployments.append(
                    DeploymentStatus(
                        platform="tailscale",
                        project_name=hostname,
                        deployment_id=pubkey[:16],
                        status=status_val,
                        url=f"tailscale://{hostname}",
                        metadata={
                            "online": online,
                            "expected": is_expected,
                            "exit_node": peer.get("ExitNode", False),
                            "exit_node_option": peer.get("ExitNodeOption", False),
                        },
                    )
                )

            # Check for missing expected nodes
            for node_name in expected_nodes:
                if node_name not in seen_nodes:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title=f"Expected node not in mesh: {node_name}",
                            description=f"{node_name} is not visible in Tailscale mesh",
                            resource=node_name,
                            remediation="Check if node is registered with Tailscale",
                        )
                    )

        except TimeoutError:
            errors.append("tailscale status timed out after 10s")
        except FileNotFoundError:
            errors.append("tailscale CLI not found")
        except json.JSONDecodeError as e:
            errors.append(f"Failed to parse tailscale status: {e}")
        except Exception as e:
            errors.append(f"Tailscale check failed: {e}")

        expected_offline = sum(
            1
            for d in deployments
            if d.metadata.get("expected") and d.status == CheckStatus.UNHEALTHY
        )

        return CheckResult(
            check_type=self.check_type,
            success=len(errors) == 0 and expected_offline == 0,
            deployments=deployments,
            findings=findings,
            errors=errors,
            metadata={
                "total_nodes": len(deployments),
                "online_nodes": sum(1 for d in deployments if d.status == CheckStatus.HEALTHY),
                "expected_offline": expected_offline,
            },
        )
