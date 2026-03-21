#!/usr/bin/env python3
"""Generate a comprehensive security report from red team analysis."""

import asyncio
import json

# Import the red team analysis
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from devguard.scripts.redteam_npm_packages import analyze_package


async def generate_report(packages: list[str], versions: dict[str, str] | None = None) -> dict:
    """Generate comprehensive security report."""
    results = []

    for package in packages:
        try:
            version = versions.get(package) if versions else None
            result = await analyze_package(package, version)
            results.append(result)
        except Exception as e:
            results.append(
                {
                    "package": package,
                    "error": str(e),
                }
            )

    # Calculate summary statistics
    total_findings = {
        "secrets": 0,
        "sensitive_files": 0,
        "obfuscated_code": 0,
        "git_history": 0,
        "lock_files": 0,
        "ci_configs": 0,
        "missing_npmignore": 0,
        "suspicious_scripts": 0,
        "placeholder_values": 0,
        "dependency_vulnerabilities": 0,
        "postinstall_scripts": 0,
        "file_permissions": 0,
        "suspicious_package_names": 0,
    }

    critical_issues = []
    warnings = []
    recommendations = []

    for result in results:
        if "error" in result or "findings" not in result:
            continue

        findings = result["findings"]

        # Count findings
        total_findings["secrets"] += len(findings.get("secrets", []))
        total_findings["sensitive_files"] += len(findings.get("sensitive_files", []))
        total_findings["obfuscated_code"] += len(findings.get("obfuscated_code", []))
        if findings.get("git_history"):
            total_findings["git_history"] += 1
        total_findings["lock_files"] += len(findings.get("lock_files", []))
        total_findings["ci_configs"] += len(findings.get("ci_configs", []))
        if findings.get("npmignore_missing"):
            total_findings["missing_npmignore"] += 1

        pkg_issues = findings.get("package_json_issues", {})
        total_findings["suspicious_scripts"] += len(pkg_issues.get("suspicious_scripts", []))
        total_findings["placeholder_values"] += len(pkg_issues.get("placeholder_values", []))
        total_findings["dependency_vulnerabilities"] += len(
            findings.get("dependency_vulnerabilities", [])
        )
        total_findings["postinstall_scripts"] += len(findings.get("postinstall_scripts", []))
        total_findings["file_permissions"] += len(findings.get("file_permissions", []))
        total_findings["suspicious_package_names"] += len(
            findings.get("suspicious_package_names", [])
        )

        # Categorize issues
        if findings.get("secrets"):
            critical_issues.append(
                {
                    "package": result["package"],
                    "type": "secrets",
                    "count": len(findings["secrets"]),
                }
            )

        if findings.get("git_history"):
            critical_issues.append(
                {
                    "package": result["package"],
                    "type": "git_history",
                    "message": ".git directory found in published package",
                }
            )

        if findings.get("npmignore_missing"):
            warnings.append(
                {
                    "package": result["package"],
                    "type": "missing_npmignore",
                    "message": "No .npmignore file found",
                }
            )

        if findings.get("obfuscated_code"):
            warnings.append(
                {
                    "package": result["package"],
                    "type": "obfuscated_code",
                    "count": len(findings["obfuscated_code"]),
                }
            )

    # Generate recommendations
    if total_findings["missing_npmignore"] > 0:
        recommendations.append(
            {
                "priority": "high",
                "action": "Add .npmignore files",
                "packages_affected": total_findings["missing_npmignore"],
                "command": "uv run python devguard/scripts/generate_npmignore.py",
            }
        )

    if total_findings["obfuscated_code"] > 0:
        recommendations.append(
            {
                "priority": "medium",
                "action": "Review obfuscated code patterns",
                "count": total_findings["obfuscated_code"],
                "note": "Ensure Function(), atob(), etc. are used legitimately",
            }
        )

    if total_findings["lock_files"] > 0:
        recommendations.append(
            {
                "priority": "low",
                "action": "Remove lock files from published packages",
                "count": total_findings["lock_files"],
            }
        )

    if total_findings["dependency_vulnerabilities"] > 0:
        critical_dep_vulns = sum(
            1
            for r in results
            if "findings" in r
            for v in r["findings"].get("dependency_vulnerabilities", [])
            if v.get("severity") in ["CRITICAL", "HIGH"]
        )
        priority = "high" if critical_dep_vulns > 0 else "medium"
        recommendations.append(
            {
                "priority": priority,
                "action": "Fix dependency vulnerabilities",
                "count": total_findings["dependency_vulnerabilities"],
                "critical_count": critical_dep_vulns,
                "command": "npm audit fix",
                "note": "Review changes before committing"
                if critical_dep_vulns > 0
                else "Update vulnerable dependencies",
            }
        )

    if total_findings["postinstall_scripts"] > 0:
        recommendations.append(
            {
                "priority": "medium",
                "action": "Review install scripts for security risks",
                "count": total_findings["postinstall_scripts"],
                "note": "Install scripts can be supply chain attack vectors",
            }
        )

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "packages_analyzed": len(packages),
        "summary": {
            "critical_issues": len(critical_issues),
            "warnings": len(warnings),
            "total_findings": total_findings,
        },
        "critical_issues": critical_issues,
        "warnings": warnings,
        "recommendations": recommendations,
        "detailed_results": results,
    }

    return report


def generate_markdown_report(report: dict) -> str:
    """Generate markdown report from JSON report."""
    lines = [
        "# NPM Package Security Report",
        "",
        f"**Generated:** {report['generated_at']}",
        f"**Packages Analyzed:** {report['packages_analyzed']}",
        "",
        "## Summary",
        "",
        f"- **Critical Issues:** {report['summary']['critical_issues']}",
        f"- **Warnings:** {report['summary']['warnings']}",
        "",
        "### Findings",
        "",
    ]

    for key, value in report["summary"]["total_findings"].items():
        if value > 0:
            lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")

    if report["critical_issues"]:
        lines.extend(
            [
                "",
                "## Critical Issues",
                "",
            ]
        )
        for issue in report["critical_issues"]:
            lines.append(f"### {issue['package']}")
            lines.append(f"- **Type:** {issue['type']}")
            if "count" in issue:
                lines.append(f"- **Count:** {issue['count']}")
            if "message" in issue:
                lines.append(f"- **Message:** {issue['message']}")
            lines.append("")

    if report["warnings"]:
        lines.extend(
            [
                "## Warnings",
                "",
            ]
        )
        for warning in report["warnings"]:
            lines.append(f"- **{warning['package']}:** {warning.get('message', warning['type'])}")
        lines.append("")

    if report["recommendations"]:
        lines.extend(
            [
                "## Recommendations",
                "",
            ]
        )
        for rec in report["recommendations"]:
            priority_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(rec["priority"], "•")
            lines.append(f"{priority_emoji} **[{rec['priority'].upper()}]** {rec['action']}")
            if "packages_affected" in rec:
                lines.append(f"  - Affects {rec['packages_affected']} package(s)")
            if "count" in rec:
                lines.append(f"  - Count: {rec['count']}")
            if "command" in rec:
                lines.append(f"  - Command: `{rec['command']}`")
            if "note" in rec:
                lines.append(f"  - Note: {rec['note']}")
            lines.append("")

    return "\n".join(lines)


async def main():
    """Main entry point."""

    # Replace with your own packages to audit
    packages = [
        "example-package",
    ]

    versions = {
        "example-package": "1.0.0",
    }

    print("Generating comprehensive security report...")
    report = await generate_report(packages, versions)

    # Save JSON report
    json_path = Path("npm_security_report.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n✓ JSON report saved to {json_path}")

    # Generate and save markdown report
    markdown = generate_markdown_report(report)
    md_path = Path("npm_security_report.md")
    md_path.write_text(markdown)

    print(f"✓ Markdown report saved to {md_path}")

    # Print summary
    print("\n" + "=" * 80)
    print("SECURITY REPORT SUMMARY")
    print("=" * 80)
    print(f"Packages analyzed: {report['packages_analyzed']}")
    print(f"Critical issues: {report['summary']['critical_issues']}")
    print(f"Warnings: {report['summary']['warnings']}")
    print("\nFindings:")
    for key, value in report["summary"]["total_findings"].items():
        if value > 0:
            print(f"  • {key}: {value}")

    if report["recommendations"]:
        print("\nRecommendations:")
        for rec in report["recommendations"]:
            print(f"  [{rec['priority'].upper()}] {rec['action']}")
            if "packages_affected" in rec:
                print(f"    Affects {rec['packages_affected']} package(s)")
            if "command" in rec:
                print(f"    Run: {rec['command']}")


if __name__ == "__main__":
    asyncio.run(main())
