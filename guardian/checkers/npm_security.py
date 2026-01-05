"""Deep npm package security analysis checker."""

import logging
import tempfile
from pathlib import Path

import httpx

from guardian.checkers.base import BaseChecker
from guardian.http_client import create_client, retry_with_backoff
from guardian.models import CheckResult, Severity, Vulnerability

logger = logging.getLogger(__name__)

# Import analysis functions from the red team script
try:
    from guardian.scripts.redteam_npm_packages import (
        analyze_package_contents,
        check_dependency_vulnerabilities,
        download_package_tarball,
        extract_tarball,
        fetch_package_info,
    )
except ImportError:
    logger.warning("npm security analysis functions not available")
    analyze_package_contents = None
    check_dependency_vulnerabilities = None
    download_package_tarball = None
    extract_tarball = None
    fetch_package_info = None


class NpmSecurityChecker(BaseChecker):
    """Deep security analysis of published npm packages."""

    check_type = "npm_security"

    async def check(self) -> CheckResult:
        """Run deep security analysis on npm packages."""
        vulnerabilities: list[Vulnerability] = []
        errors: list[str] = []

        if not self.settings.npm_packages_to_monitor:
            return CheckResult(
                check_type=self.check_type,
                success=True,
                vulnerabilities=[],
                errors=["No npm packages configured for deep security analysis"],
            )

        if not analyze_package_contents:
            return CheckResult(
                check_type=self.check_type,
                success=False,
                vulnerabilities=[],
                errors=["npm security analysis functions not available"],
            )

        for package in self.settings.npm_packages_to_monitor:
            try:
                pkg_vulns = await self._analyze_package_security(package)
                vulnerabilities.extend(pkg_vulns)
            except Exception as e:
                error_msg = f"Error analyzing package {package}: {str(e)}"
                errors.append(error_msg)
                logger.warning(error_msg)

        return CheckResult(
            check_type=self.check_type,
            success=len(errors) == 0,
            vulnerabilities=vulnerabilities,
            errors=errors,
        )

    async def _analyze_package_security(self, package: str) -> list[Vulnerability]:
        """Perform deep security analysis on a package."""
        vulnerabilities: list[Vulnerability] = []

        try:
            async with create_client() as client:
                # Get package info
                package_info = await fetch_package_info(client, package)

                # Get latest version
                dist_tags = package_info.get("dist-tags", {})
                version = dist_tags.get("latest")
                if not version:
                    versions = package_info.get("versions", {})
                    if versions:
                        version = max(versions.keys())

                if not version:
                    logger.warning(f"Could not determine version for {package}")
                    return vulnerabilities

                # Download and analyze package
                tarball_data = await download_package_tarball(client, package, version)

                # Check dependency vulnerabilities
                dep_vulns = await check_dependency_vulnerabilities(client, package, version)

                # Extract and analyze contents
                with tempfile.TemporaryDirectory() as tmpdir:
                    extract_dir = Path(tmpdir)
                    extract_tarball(tarball_data, extract_dir)

                    # Find package directory
                    package_dir = extract_dir / "package"
                    if not package_dir.exists():
                        package_dir = extract_dir

                    findings = analyze_package_contents(package_dir)

                    # Convert findings to vulnerabilities
                    vulnerabilities.extend(
                        self._convert_findings_to_vulnerabilities(
                            package, version, findings, dep_vulns
                        )
                    )

        except Exception as e:
            logger.error(f"Error in deep security analysis for {package}: {e}")
            raise

        return vulnerabilities

    def _convert_findings_to_vulnerabilities(
        self,
        package: str,
        version: str,
        findings: dict,
        dep_vulns: list[dict],
    ) -> list[Vulnerability]:
        """Convert security findings to Guardian Vulnerability objects."""
        vulnerabilities: list[Vulnerability] = []

        # Convert secrets to vulnerabilities
        for secret in findings.get("secrets", []):
            severity = self._map_severity(secret.get("severity", "medium"))
            vulnerabilities.append(
                Vulnerability(
                    package_name=package,
                    package_version=version,
                    severity=severity,
                    summary=f"Exposed secret: {secret.get('type', 'Unknown')}",
                    description=f"Secret found in {secret.get('file', 'unknown')} at line {secret.get('line', '?')}: {secret.get('match', '')[:100]}",
                    source="npm_security",
                )
            )

        # Convert sensitive files to vulnerabilities
        for file_path in findings.get("sensitive_files", []):
            vulnerabilities.append(
                Vulnerability(
                    package_name=package,
                    package_version=version,
                    severity=Severity.HIGH,
                    summary=f"Sensitive file published: {file_path}",
                    description=f"Package contains sensitive file that should not be published: {file_path}",
                    source="npm_security",
                )
            )

        # Convert obfuscated code to vulnerabilities
        for obf in findings.get("obfuscated_code", []):
            severity = self._map_severity(obf.get("severity", "low"))
            vulnerabilities.append(
                Vulnerability(
                    package_name=package,
                    package_version=version,
                    severity=severity,
                    summary=f"Obfuscated code detected: {obf.get('description', 'Unknown pattern')}",
                    description=f"Obfuscated code pattern found in package: {obf.get('match', '')[:100]}",
                    source="npm_security",
                )
            )

        # Git history is critical
        if findings.get("git_history"):
            vulnerabilities.append(
                Vulnerability(
                    package_name=package,
                    package_version=version,
                    severity=Severity.CRITICAL,
                    summary="Git history published in package",
                    description="Package contains .git directory with full commit history",
                    source="npm_security",
                )
            )

        # Missing .npmignore is a warning (medium severity)
        if findings.get("npmignore_missing"):
            vulnerabilities.append(
                Vulnerability(
                    package_name=package,
                    package_version=version,
                    severity=Severity.MEDIUM,
                    summary="Missing .npmignore file",
                    description="Package lacks .npmignore file, increasing risk of publishing sensitive files",
                    source="npm_security",
                )
            )

        # Suspicious install scripts
        pkg_issues = findings.get("package_json_issues", {})
        for script in pkg_issues.get("suspicious_scripts", []):
            vulnerabilities.append(
                Vulnerability(
                    package_name=package,
                    package_version=version,
                    severity=Severity.HIGH,
                    summary=f"Suspicious install script: {script.get('script', 'unknown')}",
                    description=f"Install script contains potentially dangerous operations: {script.get('reason', '')}",
                    source="npm_security",
                )
            )

        # Dependency vulnerabilities
        for dep_vuln in dep_vulns:
            severity = self._map_severity(dep_vuln.get("severity", "medium"))
            vulnerabilities.append(
                Vulnerability(
                    package_name=package,
                    package_version=version,
                    severity=severity,
                    summary=dep_vuln.get("title", "Dependency vulnerability"),
                    description=dep_vuln.get("overview", ""),
                    advisory_id=dep_vuln.get("id"),
                    cve_id=dep_vuln.get("cves", [None])[0] if dep_vuln.get("cves") else None,
                    source="npm_security",
                )
            )

        return vulnerabilities

    def _map_severity(self, severity_str: str) -> Severity:
        """Map string severity to Severity enum."""
        severity_lower = severity_str.lower()
        if severity_lower in ("critical", "crit"):
            return Severity.CRITICAL
        elif severity_lower in ("high", "h"):
            return Severity.HIGH
        elif severity_lower in ("medium", "med", "moderate"):
            return Severity.MEDIUM
        else:
            return Severity.LOW
