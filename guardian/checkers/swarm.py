"""Docker Swarm health checker."""

import asyncio
import json
import logging

from guardian.checkers.base import BaseChecker
from guardian.models import CheckResult, CheckStatus, DeploymentStatus, Finding, Severity

logger = logging.getLogger(__name__)


class SwarmChecker(BaseChecker):
    """Check Docker Swarm cluster health."""

    check_type = "swarm"

    # Expected nodes from ops/NODES.md
    EXPECTED_NODES = {
        "alakazam": {"role": "manager", "always_on": True},
        "gyarados": {"role": "worker", "always_on": True},
        "charizard": {"role": "worker", "always_on": False},
    }

    # Expected services from agents-stack.yml
    CRITICAL_SERVICES = [
        "arclabs-agents_sre-agent",
        "arclabs-agents_chat-api",
        "arclabs-agents_guardian-agent",
    ]

    async def check(self) -> CheckResult:
        """Check Docker Swarm cluster status."""
        deployments: list[DeploymentStatus] = []
        findings: list[Finding] = []
        errors: list[str] = []
        metadata: dict = {}

        # Check if we're in a swarm
        swarm_info = await self._get_swarm_info()
        if swarm_info.get("error"):
            errors.append(swarm_info["error"])
            return CheckResult(
                check_type=self.check_type,
                success=False,
                errors=errors,
            )

        swarm_state = swarm_info.get("state", "inactive")
        is_manager = swarm_info.get("is_manager", False)
        metadata["local_state"] = swarm_state
        metadata["is_manager"] = is_manager

        if swarm_state == "inactive":
            findings.append(
                Finding(
                    severity=Severity.WARNING,
                    title="Local node not in swarm",
                    description="This node is not part of a Docker Swarm cluster",
                    resource="swarm",
                    remediation="Run 'docker swarm init' or 'docker swarm join'",
                )
            )
            return CheckResult(
                check_type=self.check_type,
                success=True,  # Not being in swarm isn't a failure
                findings=findings,
                errors=errors,
                metadata=metadata,
            )

        # If we're a worker (not manager), we can't query cluster state
        if not is_manager:
            metadata["note"] = (
                "Running on worker node - cannot query cluster state. Run on manager node (alakazam) for full cluster visibility."
            )
            return CheckResult(
                check_type=self.check_type,
                success=True,  # Worker node is fine, just can't query
                findings=findings,
                errors=errors,
                metadata=metadata,
            )

        if swarm_state == "pending":
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Swarm node stuck in pending state",
                    description="This node is trying to join a swarm but cannot connect to the manager",
                    resource="swarm",
                    remediation="Check network connectivity to swarm manager, or run 'docker swarm leave --force' and rejoin",
                )
            )

        # If we're a manager, we can query cluster state
        if is_manager:
            nodes_result = await self._get_swarm_nodes()
            if nodes_result.get("error"):
                errors.append(nodes_result["error"])
            else:
                nodes = nodes_result.get("nodes", [])
                metadata["total_nodes"] = len(nodes)

                for node in nodes:
                    hostname = node.get("hostname", "unknown")
                    status = node.get("status", "unknown")
                    availability = node.get("availability", "unknown")
                    manager_status = node.get("manager_status", "")

                    is_healthy = status == "ready" and availability == "active"
                    expected = self.EXPECTED_NODES.get(hostname, {})

                    if is_healthy:
                        check_status = CheckStatus.HEALTHY
                    elif expected.get("always_on"):
                        check_status = CheckStatus.UNHEALTHY
                        findings.append(
                            Finding(
                                severity=Severity.HIGH,
                                title=f"Always-on swarm node unhealthy: {hostname}",
                                description=f"{hostname} status={status}, availability={availability}",
                                resource=hostname,
                                remediation=f"Check {hostname} Docker daemon and network",
                            )
                        )
                    else:
                        check_status = CheckStatus.UNKNOWN

                    deployments.append(
                        DeploymentStatus(
                            platform="swarm",
                            project_name=hostname,
                            deployment_id=node.get("id", "")[:12],
                            status=check_status,
                            url=f"docker://{hostname}",
                            metadata={
                                "status": status,
                                "availability": availability,
                                "manager_status": manager_status,
                                "role": "manager" if manager_status else "worker",
                            },
                        )
                    )

                # Check for missing expected nodes
                seen_hostnames = {n.get("hostname") for n in nodes}
                for expected_host, info in self.EXPECTED_NODES.items():
                    if expected_host not in seen_hostnames and info.get("always_on"):
                        findings.append(
                            Finding(
                                severity=Severity.HIGH,
                                title=f"Expected swarm node missing: {expected_host}",
                                description=f"{expected_host} ({info['role']}) is not in the swarm cluster",
                                resource=expected_host,
                                remediation=f"Join {expected_host} to the swarm cluster",
                            )
                        )

            # Check services
            services_result = await self._get_swarm_services()
            if services_result.get("error"):
                # Not critical - maybe no stack deployed
                logger.debug(f"Could not get swarm services: {services_result['error']}")
            else:
                services = services_result.get("services", [])
                metadata["total_services"] = len(services)

                for svc in services:
                    name = svc.get("name", "unknown")
                    replicas = svc.get("replicas", "0/0")
                    mode = svc.get("mode", "unknown")

                    # Parse replicas like "1/1" or "0/1"
                    try:
                        running, desired = replicas.split("/")
                        is_healthy = int(running) >= int(desired) and int(desired) > 0
                    except (ValueError, ZeroDivisionError):
                        is_healthy = False

                    if not is_healthy and name in self.CRITICAL_SERVICES:
                        findings.append(
                            Finding(
                                severity=Severity.HIGH,
                                title=f"Critical swarm service unhealthy: {name}",
                                description=f"Service {name} has {replicas} replicas",
                                resource=name,
                                remediation=f"Check service logs: docker service logs {name}",
                            )
                        )

                    # Check placement constraints compliance
                    placement_result = await self._check_service_placement(name)
                    if placement_result.get("violations"):
                        for violation in placement_result["violations"]:
                            findings.append(
                                Finding(
                                    severity=Severity.HIGH,
                                    title=f"Service placement violation: {name}",
                                    description=violation["description"],
                                    resource=name,
                                    remediation=violation["remediation"],
                                )
                            )

        return CheckResult(
            check_type=self.check_type,
            success=len(errors) == 0
            and not any(f.severity in [Severity.CRITICAL, Severity.HIGH] for f in findings),
            deployments=deployments,
            findings=findings,
            errors=errors,
            metadata=metadata,
        )

    async def _get_swarm_info(self) -> dict:
        """Get local swarm state."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "info",
                "--format",
                '{"state":"{{.Swarm.LocalNodeState}}","is_manager":{{.Swarm.ControlAvailable}},"node_id":"{{.Swarm.NodeID}}"}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)

            if proc.returncode != 0:
                return {"error": f"docker info failed: {stderr.decode()}"}

            return json.loads(stdout.decode())

        except asyncio.TimeoutError:
            return {"error": "docker info timed out"}
        except FileNotFoundError:
            return {"error": "docker CLI not found"}
        except json.JSONDecodeError as e:
            return {"error": f"Failed to parse docker info: {e}"}
        except Exception as e:
            return {"error": str(e)}

    async def _get_swarm_nodes(self) -> dict:
        """Get swarm nodes (requires manager)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "node",
                "ls",
                "--format",
                '{"id":"{{.ID}}","hostname":"{{.Hostname}}","status":"{{.Status}}","availability":"{{.Availability}}","manager_status":"{{.ManagerStatus}}"}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)

            if proc.returncode != 0:
                return {"error": stderr.decode()}

            nodes = []
            for line in stdout.decode().strip().split("\n"):
                if line:
                    nodes.append(json.loads(line))

            return {"nodes": nodes}

        except asyncio.TimeoutError:
            return {"error": "docker node ls timed out"}
        except Exception as e:
            return {"error": str(e)}

    async def _get_swarm_services(self) -> dict:
        """Get swarm services (requires manager)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "service",
                "ls",
                "--format",
                '{"id":"{{.ID}}","name":"{{.Name}}","mode":"{{.Mode}}","replicas":"{{.Replicas}}"}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)

            if proc.returncode != 0:
                return {"error": stderr.decode()}

            services = []
            for line in stdout.decode().strip().split("\n"):
                if line:
                    services.append(json.loads(line))

            return {"services": services}

        except asyncio.TimeoutError:
            return {"error": "docker service ls timed out"}
        except Exception as e:
            return {"error": str(e)}

    async def _check_service_placement(self, service_name: str) -> dict:
        """Check if service tasks are placed according to constraints.

        Verifies that services with node.hostname constraints are actually
        running on the correct nodes (Swarm's equivalent of K8s taints/affinities).
        """
        violations: list[dict] = []

        try:
            # Get service inspect to see constraints
            proc_inspect = await asyncio.create_subprocess_exec(
                "docker",
                "service",
                "inspect",
                service_name,
                "--format",
                "{{json .Spec.TaskTemplate.Placement.Constraints}}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_inspect, stderr_inspect = await asyncio.wait_for(
                proc_inspect.communicate(), timeout=10.0
            )

            if proc_inspect.returncode != 0:
                return {"violations": []}  # Can't check, not an error

            constraints_json = stdout_inspect.decode().strip()
            if not constraints_json or constraints_json == "null":
                return {"violations": []}  # No constraints defined

            constraints = json.loads(constraints_json) if constraints_json else []

            # Extract expected hostname from constraints (e.g., "node.hostname == alakazam")
            expected_hostname = None
            for constraint in constraints:
                if constraint.startswith("node.hostname == "):
                    expected_hostname = constraint.replace("node.hostname == ", "").strip()
                    break

            if not expected_hostname:
                return {"violations": []}  # No hostname constraint

            # Get actual task placements
            proc_ps = await asyncio.create_subprocess_exec(
                "docker",
                "service",
                "ps",
                service_name,
                "--format",
                '{"id":"{{.ID}}","node":"{{.Node}}","desired_state":"{{.DesiredState}}","current_state":"{{.CurrentState}}"}',
                "--no-trunc",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_ps, stderr_ps = await asyncio.wait_for(proc_ps.communicate(), timeout=10.0)

            if proc_ps.returncode != 0:
                return {"violations": []}  # Can't check

            # Parse task placements
            for line in stdout_ps.decode().strip().split("\n"):
                if not line:
                    continue
                try:
                    task = json.loads(line)
                    if task.get("current_state") == "Running":
                        actual_node = task.get("node", "").split(".")[
                            0
                        ]  # Extract hostname from FQDN
                        if actual_node != expected_hostname:
                            violations.append(
                                {
                                    "description": f"Service {service_name} task {task.get('id', '')[:12]} is running on {actual_node}, but constraint requires {expected_hostname}",
                                    "remediation": f"Check why task was placed on wrong node. Verify node.hostname constraint: docker service inspect {service_name}",
                                }
                            )
                except (json.JSONDecodeError, KeyError):
                    continue

            return {"violations": violations}

        except asyncio.TimeoutError:
            return {"violations": []}
        except Exception as e:
            logger.debug(f"Placement check failed for {service_name}: {e}")
            return {"violations": []}
