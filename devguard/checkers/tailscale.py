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

    # Expected nodes (Pokemon names per RFC 1178)
    EXPECTED_NODES = {
        "alakazam": {"availability": "always-on", "role": "Swarm Manager"},
        "gyarados": {"availability": "always-on", "role": "Swarm Manager, Exit Node"},
        "starmie": {"availability": "always-on", "role": "Swarm Manager"},
        "charizard": {"availability": "intermittent", "role": "Dev laptop"},
        "metagross": {"availability": "intermittent", "role": "Mac mini"},
        "snorlax": {"availability": "intermittent", "role": "NAS"},
        "kadabra": {"availability": "intermittent", "role": "iPhone"},
    }

    async def check(self) -> CheckResult:
        """Check Tailscale node status."""
        deployments: list[DeploymentStatus] = []
        findings: list[Finding] = []
        errors: list[str] = []

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
                        url=f"https://{self_name}.tailf8f94.ts.net",
                        metadata={"role": "self", "online": True},
                    )
                )

            # Check all peers
            seen_nodes = {self_node.get("HostName", "")}
            for pubkey, peer in peers.items():
                hostname = peer.get("HostName", "unknown")
                seen_nodes.add(hostname)
                online = peer.get("Online", False)

                expected = self.EXPECTED_NODES.get(hostname, {})
                is_always_on = expected.get("availability") == "always-on"

                if online:
                    status_val = CheckStatus.HEALTHY
                elif is_always_on:
                    status_val = CheckStatus.UNHEALTHY
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title=f"Always-on node offline: {hostname}",
                            description=f"{hostname} ({expected.get('role', 'unknown')}) is offline but should be always-on",
                            resource=hostname,
                            remediation=f"Check {hostname} in AWS console or via SSM",
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
                        url=f"https://{hostname}.tailf8f94.ts.net",
                        metadata={
                            "online": online,
                            "role": expected.get("role", "unknown"),
                            "availability": expected.get("availability", "unknown"),
                            "exit_node": peer.get("ExitNode", False),
                            "exit_node_option": peer.get("ExitNodeOption", False),
                        },
                    )
                )

            # Check for missing expected nodes
            for node_name, node_info in self.EXPECTED_NODES.items():
                if node_name not in seen_nodes:
                    if node_info["availability"] == "always-on":
                        findings.append(
                            Finding(
                                severity=Severity.HIGH,
                                title=f"Expected node not in mesh: {node_name}",
                                description=f"{node_name} ({node_info['role']}) is not visible in Tailscale mesh",
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

        # Count always-on nodes that are offline
        always_on_offline = sum(
            1
            for d in deployments
            if d.metadata.get("availability") == "always-on" and d.status == CheckStatus.UNHEALTHY
        )

        return CheckResult(
            check_type=self.check_type,
            success=len(errors) == 0 and always_on_offline == 0,
            deployments=deployments,
            findings=findings,
            errors=errors,
            metadata={
                "total_nodes": len(deployments),
                "online_nodes": sum(1 for d in deployments if d.status == CheckStatus.HEALTHY),
                "always_on_offline": always_on_offline,
            },
        )
