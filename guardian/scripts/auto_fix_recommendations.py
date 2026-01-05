#!/usr/bin/env python3
"""Generate automated fix recommendations based on security analysis."""

import json
import subprocess
from pathlib import Path
from typing import Any


def generate_fix_commands(
    report_path: Path = Path("npm_security_report.json"),
) -> list[dict[str, Any]]:
    """Generate fix commands based on security report."""
    if not report_path.exists():
        print(f"Error: Report not found: {report_path}")
        print("Run: uv run python guardian/scripts/generate_security_report.py")
        return []

    with open(report_path) as f:
        report = json.load(f)

    fixes = []

    # Fix missing .npmignore
    missing_npmignore = report["summary"]["total_findings"].get("missing_npmignore", 0)
    if missing_npmignore > 0:
        fixes.append(
            {
                "priority": "high",
                "issue": "Missing .npmignore files",
                "command": "uv run python guardian/scripts/generate_npmignore.py",
                "description": f"Generate .npmignore files for {missing_npmignore} package(s)",
            }
        )

    # Fix dependency vulnerabilities
    dep_vulns = report["summary"]["total_findings"].get("dependency_vulnerabilities", 0)
    if dep_vulns > 0:
        fixes.append(
            {
                "priority": "high",
                "issue": "Dependency vulnerabilities",
                "command": "npm audit fix",
                "description": f"Fix {dep_vulns} dependency vulnerabilities",
                "note": "Review changes before committing",
            }
        )

    # Review obfuscated code
    obfuscated = report["summary"]["total_findings"].get("obfuscated_code", 0)
    if obfuscated > 0:
        fixes.append(
            {
                "priority": "medium",
                "issue": "Obfuscated code patterns",
                "command": "grep -r 'Function\\|atob\\|eval' --include='*.js' --include='*.mjs' --include='*.ts'",
                "description": f"Review {obfuscated} obfuscated code patterns",
                "manual": True,
            }
        )

    return fixes


def main():
    """Main entry point."""
    fixes = generate_fix_commands()

    if not fixes:
        print("No fixes needed or report not found.")
        return

    print("=" * 80)
    print("AUTOMATED FIX RECOMMENDATIONS")
    print("=" * 80)
    print()

    high_priority = [f for f in fixes if f["priority"] == "high"]
    medium_priority = [f for f in fixes if f["priority"] == "medium"]
    low_priority = [f for f in fixes if f["priority"] == "low"]

    if high_priority:
        print("🔴 HIGH PRIORITY FIXES:")
        print()
        for fix in high_priority:
            print(f"  Issue: {fix['issue']}")
            print(f"  Description: {fix['description']}")
            print(f"  Command: {fix['command']}")
            if "note" in fix:
                print(f"  Note: {fix['note']}")
            if fix.get("manual"):
                print(f"  ⚠️  Manual review required")
            print()

    if medium_priority:
        print("🟡 MEDIUM PRIORITY FIXES:")
        print()
        for fix in medium_priority:
            print(f"  Issue: {fix['issue']}")
            print(f"  Description: {fix['description']}")
            if "command" in fix:
                print(f"  Command: {fix['command']}")
            if fix.get("manual"):
                print(f"  ⚠️  Manual review required")
            print()

    if low_priority:
        print("🟢 LOW PRIORITY FIXES:")
        print()
        for fix in low_priority:
            print(f"  Issue: {fix['issue']}")
            print(f"  Description: {fix['description']}")
            print()

    # Ask if user wants to apply fixes
    print("=" * 80)
    print("Apply fixes automatically? (y/n): ", end="")
    try:
        response = input().strip().lower()
        if response == "y":
            for fix in high_priority:
                if not fix.get("manual"):
                    print(f"\nRunning: {fix['command']}")
                    try:
                        result = subprocess.run(
                            fix["command"].split(),
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        if result.returncode == 0:
                            print(f"✓ Success: {fix['issue']}")
                        else:
                            print(f"✗ Failed: {fix['issue']}")
                            print(result.stderr)
                    except Exception as e:
                        print(f"✗ Error: {e}")
        else:
            print("Skipping automatic fixes. Run commands manually as needed.")
    except (EOFError, KeyboardInterrupt):
        print("\nSkipping automatic fixes.")


if __name__ == "__main__":
    main()
