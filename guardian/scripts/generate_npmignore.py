#!/usr/bin/env python3
"""Generate .npmignore files for npm packages based on best practices."""

import json
from pathlib import Path
from typing import Any


def generate_npmignore_content(
    package_dir: Path, package_json: dict[str, Any] | None = None
) -> str:
    """Generate .npmignore content based on package structure and best practices."""
    lines = [
        "# .npmignore - Files excluded from npm package",
        "# Generated based on npm best practices",
        "",
        "# Test files",
        "test/",
        "tests/",
        "__tests__/",
        "*.test.js",
        "*.test.ts",
        "*.test.mjs",
        "*.spec.js",
        "*.spec.ts",
        "*.spec.mjs",
        "",
        "# Coverage reports",
        "coverage/",
        ".nyc_output/",
        "*.lcov",
        "",
        "# Development configuration",
        ".eslintrc*",
        ".prettierrc*",
        ".editorconfig",
        ".mocharc*",
        "jest.config.*",
        "vitest.config.*",
        "",
        "# CI/CD configuration (may contain secrets)",
        ".github/",
        ".gitlab-ci.yml",
        ".circleci/",
        ".travis.yml",
        ".drone.yml",
        "azure-pipelines.yml",
        "Jenkinsfile",
        "",
        "# Environment and secrets",
        ".env",
        ".env.*",
        "*.env",
        ".secrets",
        "secrets.json",
        "credentials.json",
        "config.json",
        "",
        "# Lock files",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "",
        "# Git",
        ".git/",
        ".gitignore",
        ".gitattributes",
        "",
        "# IDE and editor files",
        ".vscode/",
        ".idea/",
        "*.swp",
        "*.swo",
        "*~",
        ".DS_Store",
        "",
        "# Build artifacts (if source is published)",
        "dist/",
        "build/",
        "*.map",
        "",
        "# Documentation (optional - remove if you want docs in package)",
        "# docs/",
        "# *.md",
        "# README.md is always included by npm",
        "",
        "# Temporary files",
        "*.tmp",
        "*.log",
        "*.cache",
        "",
        "# Source files (if publishing compiled code only)",
        "# Uncomment if you only publish compiled output:",
        "# src/",
        "# *.ts",
        "# tsconfig.json",
    ]

    return "\n".join(lines) + "\n"


def find_package_directories(base_path: Path) -> list[Path]:
    """Find all package.json files to generate .npmignore for."""
    packages = []
    for pkg_json in base_path.rglob("package.json"):
        # Skip node_modules
        if "node_modules" in pkg_json.parts:
            continue
        packages.append(pkg_json.parent)
    return packages


def main():
    """Main entry point."""
    import sys

    if len(sys.argv) > 1:
        base_path = Path(sys.argv[1])
    else:
        # Default to common dev locations
        base_path = Path.home() / "Documents" / "dev"

    if not base_path.exists():
        print(f"Error: Path does not exist: {base_path}")
        return

    packages = find_package_directories(base_path)

    if not packages:
        print(f"No package.json files found in {base_path}")
        return

    print(f"Found {len(packages)} packages")
    print()

    for pkg_dir in packages:
        npmignore_path = pkg_dir / ".npmignore"

        # Check if package.json exists
        pkg_json_path = pkg_dir / "package.json"
        package_json = None
        if pkg_json_path.exists():
            try:
                with open(pkg_json_path) as f:
                    package_json = json.load(f)
            except Exception:
                pass

        # Generate .npmignore
        content = generate_npmignore_content(pkg_dir, package_json)

        # Check if it already exists
        if npmignore_path.exists():
            existing = npmignore_path.read_text()
            if existing.strip() == content.strip():
                print(f"✓ {pkg_dir.name}: .npmignore already up to date")
                continue
            else:
                print(f"⚠ {pkg_dir.name}: .npmignore exists but differs")
                print(f"  Backup existing file? (y/n): ", end="")
                # For automation, we'll create a backup
                backup_path = npmignore_path.with_suffix(".npmignore.backup")
                npmignore_path.rename(backup_path)
                print(f"  Backed up to {backup_path.name}")

        # Write new .npmignore
        npmignore_path.write_text(content)
        print(f"✓ {pkg_dir.name}: Created/updated .npmignore")

    print()
    print("Done! Review the generated .npmignore files and customize as needed.")


if __name__ == "__main__":
    main()
