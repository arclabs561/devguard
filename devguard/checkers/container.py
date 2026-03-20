"""Container security checker."""

import logging
import re
from pathlib import Path
from typing import ClassVar

from devguard.checkers.base import BaseChecker
from devguard.models import CheckResult, Severity, Vulnerability

logger = logging.getLogger(__name__)


class ContainerChecker(BaseChecker):
    """Check Dockerfiles for security best practices."""

    check_type: ClassVar[str] = "container"

    # Simple regex-based rules
    RULES = [
        {
            "id": "run-as-root",
            "pattern": r"^USER\s+root",
            "severity": Severity.HIGH,
            "summary": "Running as root user",
            "description": "The container explicitly switches to root user. Use a non-privileged user instead.",
        },
        {
            "id": "missing-user",
            "severity": Severity.MEDIUM,
            "summary": "No USER instruction",
            "description": "Dockerfile does not switch to a non-privileged user. It will likely run as root.",
            "check_func": lambda content: not re.search(r"^USER\s+", content, re.MULTILINE),
        },
        {
            "id": "latest-tag",
            "pattern": r"^FROM\s+[^:]+:latest",
            "severity": Severity.MEDIUM,
            "summary": "Using 'latest' tag",
            "description": "Using the 'latest' tag makes builds non-reproducible and can introduce unexpected breaking changes.",
        },
        {
            "id": "add-usage",
            "pattern": r"^ADD\s+",
            "severity": Severity.LOW,
            "summary": "Using ADD instruction",
            "description": "Use COPY instead of ADD unless you specifically need to extract tarballs or fetch remote URLs.",
        },
        {
            "id": "exposed-secrets",
            "pattern": r"(API_KEY|SECRET|PASSWORD|TOKEN)\s*=",
            "severity": Severity.CRITICAL,
            "summary": "Potential secret in Dockerfile",
            "description": "Found a potential secret/credential embedded directly in the Dockerfile.",
        },
        {
            "id": "sudo-usage",
            "pattern": r"sudo\s+",
            "severity": Severity.HIGH,
            "summary": "Using sudo",
            "description": "Avoid installing or using sudo in containers. It increases the attack surface.",
        },
    ]

    async def check(self) -> CheckResult:
        """Check Dockerfiles."""
        vulnerabilities: list[Vulnerability] = []
        errors: list[str] = []
        metadata: dict = {"files_scanned": []}

        # Find Dockerfiles
        dockerfiles = self._find_dockerfiles()

        for df in dockerfiles:
            try:
                vulns = self._scan_dockerfile(df)
                vulnerabilities.extend(vulns)
                metadata["files_scanned"].append(str(df))
            except Exception as e:
                errors.append(f"Error scanning {df}: {str(e)}")

        return CheckResult(
            check_type=self.check_type,
            success=len(vulnerabilities) == 0 and len(errors) == 0,
            vulnerabilities=vulnerabilities,
            errors=errors,
            metadata=metadata,
        )

    def _find_dockerfiles(self) -> list[Path]:
        """Find Dockerfiles in current directory and subdirs."""
        # Use simple recursion or glob
        # We limit depth to avoid massive scans
        base = Path.cwd()
        found = []

        # Check explicit "Dockerfile"
        for path in base.rglob("Dockerfile*"):
            if path.is_file() and "node_modules" not in str(path) and ".git" not in str(path):
                found.append(path)

        return found

    def _scan_dockerfile(self, path: Path) -> list[Vulnerability]:
        """Scan a single Dockerfile."""
        vulns = []
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return []

        for rule in self.RULES:
            match = False

            if "check_func" in rule:
                if rule["check_func"](content):  # type: ignore
                    match = True
            elif "pattern" in rule:
                if re.search(rule["pattern"], content, re.MULTILINE | re.IGNORECASE):  # type: ignore
                    match = True

            if match:
                vulns.append(
                    Vulnerability(
                        package_name=f"Dockerfile:{path.name}",
                        package_version="N/A",
                        severity=rule["severity"],  # type: ignore
                        summary=rule["summary"],  # type: ignore
                        description=rule["description"],  # type: ignore
                        source="devguard-container-check",
                        references=[
                            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"
                        ],
                    )
                )

        return vulns
