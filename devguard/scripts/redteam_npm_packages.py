#!/usr/bin/env python3
"""Red team analysis of npm packages for secrets and sensitive data."""

import asyncio
import base64
import binascii
import json
import logging
import re

# Import retry logic from devguard
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

devguard_path = Path(__file__).parent.parent.parent
sys.path.insert(0, str(devguard_path))
from devguard.http_client import retry_with_backoff

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Patterns for detecting secrets
SECRET_PATTERNS = [
    # API keys
    (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Key"),
    (r'["\']?api[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Token"),
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (
        r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9+/=]{40})["\']',
        "AWS Secret Key",
    ),
    # GitHub tokens
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r'github[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{36,})["\']', "GitHub Token"),
    # Generic tokens
    (r'["\']?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,})["\']', "Token"),
    (r'["\']?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-+/=]{20,})["\']', "Secret"),
    (r'["\']?password["\']?\s*[:=]\s*["\']([^\'"\s]{8,})["\']', "Password"),
    # Private keys
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "Private Key"),
    (r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----", "EC Private Key"),
    # Database URLs
    (r'["\']?database[_-]?url["\']?\s*[:=]\s*["\']([^\'"]+)["\']', "Database URL"),
    (r'postgresql://[^\'"\s]+', "PostgreSQL URL"),
    (r'mongodb://[^\'"\s]+', "MongoDB URL"),
    (r'mysql://[^\'"\s]+', "MySQL URL"),
    # OAuth
    (
        r'["\']?client[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
        "OAuth Client Secret",
    ),
    # JWT secrets
    (r'["\']?jwt[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-+/=]{20,})["\']', "JWT Secret"),
    # Slack tokens
    (r"xox[baprs]-[0-9a-zA-Z\-]{10,}", "Slack Token"),
    # Stripe keys
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key"),
    (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test Secret Key"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Live Publishable Key"),
    # Email credentials
    (r'smtp[_-]?password["\']?\s*[:=]\s*["\']([^\'"]+)["\']', "SMTP Password"),
    # OpenAI/Anthropic keys
    (r"sk-[a-zA-Z0-9]{32,}", "OpenAI API Key"),
    (r"sk-ant-[a-zA-Z0-9\-_]{95,}", "Anthropic API Key"),
    # Placeholder values that weren't replaced (must have at least 2 words/parts)
    (r'["\']?(YOUR_|PLACEHOLDER_|REPLACE_|CHANGE_)[A-Z_]{5,}["\']?', "Unreplaced Placeholder"),
    (r'["\']?(TODO_|FIXME_)[A-Z_]{8,}["\']?', "Unreplaced Placeholder"),  # Longer for TODO/FIXME
]

# Sensitive file patterns
SENSITIVE_FILES = [
    r"\.env",
    r"\.env\.local",
    r"\.env\.production",
    r"\.env\.development",
    r"\.secrets",
    r"secrets\.json",
    r"config\.json",
    r"credentials\.json",
    r"id_rsa",
    r"id_ed25519",
    r"\.pem",
    r"\.key",
    r"\.p12",
    r"\.pfx",
    r"\.jks",
    r"\.keystore",
]


async def fetch_package_info(client: httpx.AsyncClient, package: str) -> dict[str, Any]:
    """Fetch package metadata from npm registry."""
    encoded_package = quote(package, safe="")
    url = f"https://registry.npmjs.org/{encoded_package}"

    response = await client.get(url, timeout=30.0)
    response.raise_for_status()
    return response.json()


async def download_package_tarball(client: httpx.AsyncClient, package: str, version: str) -> bytes:
    """Download package tarball from npm registry."""
    encoded_package = quote(package, safe="")
    url = f"https://registry.npmjs.org/{encoded_package}/-/{package.split('/')[-1]}-{version}.tgz"

    response = await client.get(url, timeout=60.0, follow_redirects=True)
    response.raise_for_status()
    return response.content


def extract_tarball(tarball_data: bytes, extract_to: Path) -> None:
    """Extract tarball to directory."""
    with tempfile.NamedTemporaryFile(suffix=".tgz", delete=False) as tmp:
        tmp.write(tarball_data)
        tmp_path = Path(tmp.name)

    try:
        with tarfile.open(tmp_path, "r:gz") as tar:
            # Use filter='data' to avoid security warnings while allowing extraction
            # This is safe for npm packages from the official registry
            tar.extractall(extract_to, filter="data")
    finally:
        tmp_path.unlink()


def is_base64_encoded(s: str) -> bool:
    """Check if string is valid base64."""
    try:
        if len(s) < 20:  # Too short to be meaningful
            return False
        decoded = base64.b64decode(s, validate=True)
        # Check if decoded data looks like text (not binary)
        return all(32 <= b <= 126 or b in (9, 10, 13) for b in decoded[:100])
    except Exception:
        return False


def is_hex_encoded(s: str) -> bool:
    """Check if string is valid hex."""
    try:
        if len(s) < 20 or len(s) % 2 != 0:
            return False
        decoded = binascii.unhexlify(s)
        # Check if decoded data looks like text
        return all(32 <= b <= 126 or b in (9, 10, 13) for b in decoded[:100])
    except Exception:
        return False


def scan_for_obfuscated_code(content: str) -> list[dict[str, Any]]:
    """Scan for obfuscated code patterns with context-aware detection."""
    findings = []

    # Patterns indicating obfuscation
    obfuscation_patterns = [
        (r"eval\s*\(", "eval() usage - potential code obfuscation"),
        (r"Function\s*\(", "Function() constructor - potential code obfuscation"),
        (r"atob\s*\(", "atob() - base64 decoding at runtime"),
        (r"btoa\s*\(", "btoa() - base64 encoding at runtime"),
        (r"String\.fromCharCode\s*\(", "String.fromCharCode - potential string obfuscation"),
        (r"unescape\s*\(", "unescape() - deprecated, potential obfuscation"),
        (r"decodeURIComponent\s*\(", "decodeURIComponent in suspicious context"),
        (r'\[["\']\w+["\']\]\s*\(', "Bracket notation function calls - potential obfuscation"),
    ]

    # Legitimate use patterns (reduce false positives)
    legitimate_patterns = [
        r"//.*test|spec|example",  # In test/example context
        r"/\*.*test|spec|example.*\*/",  # In comments
        r"console\.(log|debug)",  # Near console.log (likely debugging)
        r"JSON\.parse",  # JSON parsing is legitimate
        r"Buffer\.from",  # Buffer operations are legitimate
    ]

    for pattern, description in obfuscation_patterns:
        matches = list(re.finditer(pattern, content, re.IGNORECASE))
        if matches:
            for match in matches:
                context_start = max(0, match.start() - 200)
                context_end = min(len(content), match.end() + 200)
                context = content[context_start:context_end]

                # Skip if in legitimate context
                is_legitimate = any(
                    re.search(legit_pattern, context, re.IGNORECASE)
                    for legit_pattern in legitimate_patterns
                )
                if is_legitimate:
                    continue

                # Check for base64-like strings nearby
                has_base64_nearby = bool(re.search(r"[A-Za-z0-9+/]{30,}={0,2}", context))

                # Check for suspicious variable names (often used in obfuscation)
                has_suspicious_vars = bool(re.search(r"\b[_$][a-z]{1,3}\b", context))

                # Check for long hex strings (another obfuscation technique)
                has_hex_strings = bool(
                    re.search(r'["\'][0-9a-f]{40,}["\']', context, re.IGNORECASE)
                )

                # Determine severity based on multiple factors
                suspicious_factors = sum(
                    [
                        has_base64_nearby,
                        has_suspicious_vars,
                        has_hex_strings,
                    ]
                )

                severity = (
                    "HIGH"
                    if suspicious_factors >= 2
                    else ("MEDIUM" if suspicious_factors >= 1 else "LOW")
                )

                findings.append(
                    {
                        "type": "Obfuscated Code",
                        "line": content[: match.start()].count("\n") + 1,
                        "match": match.group(0),
                        "description": description,
                        "has_base64_nearby": has_base64_nearby,
                        "has_suspicious_vars": has_suspicious_vars,
                        "has_hex_strings": has_hex_strings,
                        "suspicious_factors": suspicious_factors,
                        "severity": severity,
                    }
                )

    return findings


def scan_for_encoded_secrets(content: str) -> list[dict[str, Any]]:
    """Scan for base64/hex encoded secrets."""
    findings = []

    # Find potential base64 strings (20+ chars, base64 charset)
    base64_pattern = r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']'
    for match in re.finditer(base64_pattern, content):
        candidate = match.group(1)
        if is_base64_encoded(candidate):
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
                # Check if decoded content looks like a secret
                if any(
                    keyword in decoded.lower()
                    for keyword in ["password", "secret", "key", "token", "api"]
                ):
                    findings.append(
                        {
                            "type": "Base64 Encoded Secret",
                            "line": content[: match.start()].count("\n") + 1,
                            "match": candidate[:50] + "..." if len(candidate) > 50 else candidate,
                            "decoded_preview": decoded[:50] + "..."
                            if len(decoded) > 50
                            else decoded,
                            "severity": "HIGH",
                        }
                    )
            except Exception:
                pass

    # Find potential hex strings
    hex_pattern = r'["\']([0-9a-fA-F]{40,})["\']'
    for match in re.finditer(hex_pattern, content):
        candidate = match.group(1)
        if is_hex_encoded(candidate):
            try:
                decoded = binascii.unhexlify(candidate).decode("utf-8", errors="ignore")
                if any(
                    keyword in decoded.lower() for keyword in ["password", "secret", "key", "token"]
                ):
                    findings.append(
                        {
                            "type": "Hex Encoded Secret",
                            "line": content[: match.start()].count("\n") + 1,
                            "match": candidate[:50] + "..." if len(candidate) > 50 else candidate,
                            "decoded_preview": decoded[:50] + "..."
                            if len(decoded) > 50
                            else decoded,
                            "severity": "HIGH",
                        }
                    )
            except Exception:
                pass

    return findings


def scan_file_for_secrets(file_path: Path) -> list[dict[str, Any]]:
    """Scan a file for secret patterns."""
    findings = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        logger.debug(f"Could not read {file_path}: {e}")
        return findings

    # Standard pattern matching
    for pattern, secret_type in SECRET_PATTERNS:
        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            # Extract the secret value (group 1 if available, else full match)
            secret_value = match.group(1) if match.groups() else match.group(0)

            # Skip obvious test/example values
            test_indicators = [
                "test",
                "example",
                "sample",
                "demo",
                "placeholder",
                "123456",
                "abcdef",
                "xxxxx",
                "yyyyy",
                "dummy",
                "your_",
                "replace_",
                "change_",
                "todo_",
            ]
            secret_lower = secret_value.lower()
            if any(indicator in secret_lower for indicator in test_indicators):
                # Check if it's in a test file or documentation
                file_lower = str(file_path).lower()
                if any(
                    doc_indicator in file_lower
                    for doc_indicator in ["test", "spec", "example", "doc", "readme", ".md"]
                ):
                    continue  # Skip test/example values in test/docs

            # Truncate for display
            display_value = secret_value[:50] + "..." if len(secret_value) > 50 else secret_value

            findings.append(
                {
                    "type": secret_type,
                    "file": str(file_path),
                    "line": content[: match.start()].count("\n") + 1,
                    "match": display_value,
                    "severity": "HIGH",
                }
            )

    # Check for encoded secrets
    encoded_secrets = scan_for_encoded_secrets(content)
    for finding in encoded_secrets:
        finding["file"] = str(file_path)
        findings.append(finding)

    return findings


def scan_for_sensitive_files(root: Path) -> list[dict[str, Any]]:
    """Scan for sensitive file names."""
    findings = []

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue

        file_name = file_path.name
        file_path_str = str(file_path.relative_to(root))

        # Skip example files (they're usually safe)
        if ".example" in file_name.lower() or file_name.endswith(".example"):
            continue

        for pattern in SENSITIVE_FILES:
            if re.search(pattern, file_name, re.IGNORECASE):
                # Check if file contains actual secrets
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    # Look for actual secret patterns in the file
                    has_secrets = False
                    for secret_pattern, _ in SECRET_PATTERNS[:10]:  # Check first 10 patterns
                        if re.search(secret_pattern, content, re.IGNORECASE):
                            has_secrets = True
                            break

                    if has_secrets:
                        findings.append(
                            {
                                "type": "Sensitive File with Secrets",
                                "file": file_path_str,
                                "description": f"File matches sensitive pattern AND contains secrets: {pattern}",
                                "severity": "CRITICAL",
                            }
                        )
                    else:
                        findings.append(
                            {
                                "type": "Sensitive File",
                                "file": file_path_str,
                                "description": f"File matches sensitive pattern: {pattern}",
                                "severity": "MEDIUM",
                            }
                        )
                except Exception:
                    # If we can't read it, still flag it
                    findings.append(
                        {
                            "type": "Sensitive File",
                            "file": file_path_str,
                            "description": f"File matches sensitive pattern: {pattern}",
                            "severity": "MEDIUM",
                        }
                    )
                break

    return findings


def analyze_package_json(pkg_json: dict[str, Any]) -> dict[str, Any]:
    """Deep analysis of package.json."""
    issues = {
        "suspicious_scripts": [],
        "missing_fields": [],
        "exposed_repos": [],
        "placeholder_values": [],
        "files_field_issues": [],
        "recommendations": [],
    }

    # Check if files field is set (more secure than .npmignore)
    if "files" not in pkg_json:
        issues["recommendations"].append(
            "Consider using 'files' field in package.json instead of .npmignore for explicit allowlist"
        )
    else:
        files_list = pkg_json.get("files", [])
        # Check for common missing entries
        if "package.json" not in files_list:
            issues["files_field_issues"].append(
                "package.json should be in files list (though npm includes it anyway)"
            )

        # Warn if files list is very large (might be too permissive)
        if len(files_list) > 50:
            issues["files_field_issues"].append(
                f"Files list is very large ({len(files_list)} entries) - consider being more selective"
            )

    # Check scripts for suspicious patterns
    scripts = pkg_json.get("scripts", {})
    suspicious_patterns = [
        (r"eval\s*\(", "eval in script"),
        (r"curl.*http", "HTTP request in script"),
        (r"wget.*http", "HTTP request in script"),
        (r"\$.*API.*KEY", "API key reference"),
        (r"\$.*SECRET", "Secret reference"),
        (r"base64.*-d", "base64 decode"),
        (r"\.env", "Environment file access"),
    ]

    # Check for postinstall/preinstall scripts (common attack vector)
    install_scripts = ["postinstall", "preinstall", "install"]
    for script_name in install_scripts:
        if script_name in scripts:
            script_content = scripts[script_name]
            # Check for network requests in install scripts
            if re.search(r"(curl|wget|fetch|axios|http)", script_content, re.IGNORECASE):
                issues["suspicious_scripts"].append(
                    {
                        "script": script_name,
                        "issue": f"{script_name} script makes network requests - potential supply chain risk",
                        "content": script_content[:100],
                    }
                )

    for script_name, script_content in scripts.items():
        for pattern, description in suspicious_patterns:
            if re.search(pattern, script_content, re.IGNORECASE):
                issues["suspicious_scripts"].append(
                    {
                        "script": script_name,
                        "issue": description,
                        "content": script_content[:100],
                    }
                )

    # Check for placeholder values
    pkg_str = json.dumps(pkg_json, indent=2)
    placeholder_patterns = [
        r"YOUR_[A-Z_]+",
        r"PLACEHOLDER_[A-Z_]+",
        r"REPLACE_[A-Z_]+",
        r"CHANGE_[A-Z_]+",
        r"<YOUR_[^>]+>",
        r"\[TODO:[^\]]+\]",
    ]

    # Check dependencies for known risky packages
    dependencies = pkg_json.get("dependencies", {})
    dev_dependencies = pkg_json.get("devDependencies", {})
    all_deps = {**dependencies, **dev_dependencies}

    # Known risky patterns in package names
    risky_patterns = [
        r"^eslint-config-",  # Often used for supply chain attacks
        r"^@types/",  # TypeScript types - generally safe but check
    ]

    # Check for typosquatting patterns (very basic)
    for dep_name in all_deps.keys():
        # Check for suspicious characters or patterns
        if any(char in dep_name for char in ["__", "--", ".."]):
            issues["recommendations"].append(
                f"Review dependency '{dep_name}' - suspicious characters in name"
            )
    for pattern in placeholder_patterns:
        matches = re.finditer(pattern, pkg_str, re.IGNORECASE)
        for match in matches:
            issues["placeholder_values"].append(
                {
                    "match": match.group(0),
                    "description": "Unreplaced placeholder in package.json",
                }
            )

    # Check repository URLs for private repos
    repo = pkg_json.get("repository")
    if repo:
        if isinstance(repo, dict):
            repo_url = repo.get("url", "")
        else:
            repo_url = str(repo)

        # Check for private repo indicators
        if any(
            domain in repo_url.lower() for domain in ["github.com", "gitlab.com", "bitbucket.org"]
        ):
            # Check if it's a private repo format (could expose internal structure)
            if "/private/" in repo_url or "/internal/" in repo_url:
                issues["exposed_repos"].append(
                    {
                        "url": repo_url,
                        "issue": "Potentially private repository URL exposed",
                    }
                )

    return issues


def analyze_package_contents(package_dir: Path) -> dict[str, Any]:
    """Analyze package contents for secrets and sensitive data."""
    findings = {
        "secrets": [],
        "sensitive_files": [],
        "package_json": None,
        "package_json_issues": None,
        "large_files": [],
        "source_maps": [],
        "test_files_with_secrets": [],
        "obfuscated_code": [],
        "git_history": False,
        "lock_files": [],
        "ci_configs": [],
        "npmignore_missing": False,
        "comments_with_secrets": [],
        "postinstall_scripts": [],
        "dependency_risks": [],
        "file_permissions": [],
        "suspicious_package_names": [],
    }

    # Check for package.json
    package_json_path = package_dir / "package" / "package.json"
    if not package_json_path.exists():
        # Try root level
        package_json_path = package_dir / "package.json"

    if package_json_path.exists():
        try:
            with open(package_json_path) as f:
                findings["package_json"] = json.load(f)
                findings["package_json_issues"] = analyze_package_json(findings["package_json"])
        except Exception as e:
            logger.warning(f"Could not parse package.json: {e}")

    # Check for .npmignore
    npmignore_path = package_dir / "package" / ".npmignore"
    if not npmignore_path.exists():
        npmignore_path = package_dir / ".npmignore"
    findings["npmignore_missing"] = not npmignore_path.exists()

    # Check for .git directory (shouldn't be published)
    git_dir = package_dir / "package" / ".git"
    if not git_dir.exists():
        git_dir = package_dir / ".git"
    findings["git_history"] = git_dir.exists() and git_dir.is_dir()

    # Check package name for suspicious patterns (typosquatting indicators)
    if findings["package_json"]:
        pkg_name = findings["package_json"].get("name", "")
        suspicious_patterns = [
            (r"__", "Double underscore - potential typosquatting"),
            (r"--", "Double dash - potential typosquatting"),
            (r"\.\.", "Double dot - potential path traversal"),
            (r"[A-Z]{3,}", "All caps - unusual naming"),
        ]
        for pattern, reason in suspicious_patterns:
            if re.search(pattern, pkg_name):
                findings["suspicious_package_names"].append(
                    {
                        "pattern": pattern,
                        "reason": reason,
                        "severity": "MEDIUM",
                    }
                )

    # Scan all files for secrets
    for file_path in package_dir.rglob("*"):
        if not file_path.is_file():
            continue

        # Skip node_modules if present
        if "node_modules" in file_path.parts:
            continue

        # Check file size (flag files > 1MB)
        try:
            file_size = file_path.stat().st_size
            if file_size > 1_000_000:  # 1MB
                findings["large_files"].append(
                    {
                        "file": str(file_path.relative_to(package_dir)),
                        "size_mb": round(file_size / 1_000_000, 2),
                        "severity": "LOW",
                    }
                )

            # Check file permissions (executable files in packages can be suspicious)
            file_stat = file_path.stat()
            is_executable = bool(file_stat.st_mode & 0o111)  # Check execute bit
            if is_executable and file_path.suffix not in [
                ".sh",
                ".bash",
                ".zsh",
                ".mjs",
                ".js",
                ".ts",
            ]:
                findings["file_permissions"].append(
                    {
                        "file": str(file_path.relative_to(package_dir)),
                        "issue": "Executable file with unusual extension",
                        "severity": "LOW",
                    }
                )
        except Exception:
            pass

        # Check for source maps
        if file_path.suffix == ".map":
            findings["source_maps"].append(
                {
                    "file": str(file_path.relative_to(package_dir)),
                    "description": "Source map file - may expose source code structure",
                    "severity": "LOW",
                }
            )

        # Check for lock files (shouldn't be published)
        if file_path.name in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]:
            findings["lock_files"].append(
                {
                    "file": str(file_path.relative_to(package_dir)),
                    "description": "Lock file should not be published",
                    "severity": "LOW",
                }
            )

        # Check for CI/CD configs (may contain secrets)
        ci_patterns = [
            r"\.github/workflows/",
            r"\.gitlab-ci\.yml",
            r"\.circleci/",
            r"\.travis\.yml",
            r"\.drone\.yml",
            r"azure-pipelines\.yml",
            r"Jenkinsfile",
        ]
        file_path_str = str(file_path.relative_to(package_dir))
        for pattern in ci_patterns:
            if re.search(pattern, file_path_str, re.IGNORECASE):
                findings["ci_configs"].append(
                    {
                        "file": file_path_str,
                        "description": "CI/CD configuration file - may contain secrets",
                        "severity": "MEDIUM",
                    }
                )
                break

        # Skip binary files (rough heuristic)
        try:
            content = file_path.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, IsADirectoryError):
            continue

        # Check if it's a test file
        is_test_file = (
            "test" in file_path.name.lower()
            or "spec" in file_path.name.lower()
            or "test" in str(file_path.parent).lower()
        )

        secrets = scan_file_for_secrets(file_path)
        findings["secrets"].extend(secrets)

        # If secrets found in test files, flag separately
        if secrets and is_test_file:
            findings["test_files_with_secrets"].extend(secrets)

        # Check for obfuscated code (skip documentation files)
        file_lower = str(file_path).lower()
        is_doc_file = any(
            ext in file_lower
            for ext in [".md", ".txt", ".rst", ".adoc", "readme", "changelog", "license"]
        )
        if not is_doc_file:
            obfuscated = scan_for_obfuscated_code(content)
            for obf in obfuscated:
                obf["file"] = str(file_path.relative_to(package_dir))
                findings["obfuscated_code"].append(obf)

        # Check comments for secrets (especially TODO/FIXME with sensitive info)
        # Only flag if it looks like an actual secret, not just mentions the word
        comment_patterns = [
            # More specific patterns to reduce false positives
            (
                r'//.*(?:password|secret|key|token|api[_-]?key)\s*[:=]\s*["\']([^\'"]{15,})["\']',
                "Secret in comment",
            ),
            (
                r'#.*(?:password|secret|key|token|api[_-]?key)\s*[:=]\s*["\']([^\'"]{15,})["\']',
                "Secret in comment",
            ),
            (
                r'/\*.*(?:password|secret|key|token|api[_-]?key)\s*[:=]\s*["\']([^\'"]{15,})["\'].*\*/',
                "Secret in comment",
            ),
            # TODO/FIXME with sensitive keywords (but not documentation about them)
            (
                r"(?:TODO|FIXME|XXX|HACK)[^:]*[:][^X]*(?:password|secret|key|token|api[_-]?key|credential)",
                "TODO with sensitive keyword",
            ),
        ]
        for pattern, desc in comment_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            for match in matches:
                # Skip if it's clearly a URL or example
                match_text = match.group(0).lower()
                if any(
                    skip in match_text
                    for skip in ["http://", "https://", "github.com", "example.com", "//", "www."]
                ):
                    continue
                findings["comments_with_secrets"].append(
                    {
                        "file": str(file_path.relative_to(package_dir)),
                        "line": content[: match.start()].count("\n") + 1,
                        "match": match.group(0)[:100],
                        "description": desc,
                        "severity": "MEDIUM",
                    }
                )

    # Scan for sensitive file names
    findings["sensitive_files"] = scan_for_sensitive_files(package_dir)

    # Check for postinstall scripts in package.json
    if findings["package_json"]:
        scripts = findings["package_json"].get("scripts", {})
        install_scripts = ["postinstall", "preinstall", "install"]
        for script_name in install_scripts:
            if script_name in scripts:
                script_content = scripts[script_name]
                findings["postinstall_scripts"].append(
                    {
                        "script": script_name,
                        "content": script_content,
                        "severity": "MEDIUM",
                        "note": "Install scripts can be security risks - review carefully",
                    }
                )

    return findings


async def check_dependency_vulnerabilities(
    client: httpx.AsyncClient, package: str, version: str
) -> list[dict[str, Any]]:
    """Check for known vulnerabilities in package dependencies."""
    vulnerabilities = []

    try:
        # Use npm audit API
        audit_payload = {
            "name": f"devguard-check-{package}",
            "version": "1.0.0",
            "requires": {package: version},
            "dependencies": {
                package: {
                    "version": version,
                }
            },
        }

        async def fetch_audit():
            response = await client.post(
                "https://registry.npmjs.org/-/npm/v1/security/audits",
                json=audit_payload,
                timeout=30.0,
            )
            response.raise_for_status()
            return response

        try:
            audit_response = await retry_with_backoff(fetch_audit, max_retries=3)
            audit_data = audit_response.json()

            advisories = audit_data.get("advisories", {})
            for advisory_id, advisory_data in advisories.items():
                severity_map = {
                    "low": "LOW",
                    "moderate": "MEDIUM",
                    "high": "HIGH",
                    "critical": "CRITICAL",
                }

                severity = severity_map.get(
                    advisory_data.get("severity", "moderate").lower(), "MEDIUM"
                )

                cves = advisory_data.get("cves", [])
                cve_id = cves[0] if cves else None

                vulnerabilities.append(
                    {
                        "advisory_id": advisory_id,
                        "severity": severity,
                        "title": advisory_data.get("title"),
                        "description": advisory_data.get("overview", "")[:200],
                        "cve": cve_id,
                        "vulnerable_versions": advisory_data.get("vulnerable_versions", []),
                    }
                )
        except httpx.HTTPStatusError as e:
            if e.response.status_code != 404:
                logger.debug(f"Could not check vulnerabilities for {package}: {e}")
        except Exception as e:
            logger.debug(f"Error checking vulnerabilities: {e}")
    except Exception as e:
        logger.debug(f"Error in vulnerability check: {e}")

    return vulnerabilities


async def analyze_package(package: str, version: str | None = None) -> dict[str, Any]:
    """Analyze a single npm package."""
    logger.info(f"Analyzing {package}@{version or 'latest'}")

    async with httpx.AsyncClient() as client:
        # Get package info
        package_info = await fetch_package_info(client, package)

        # Determine version
        if not version:
            dist_tags = package_info.get("dist-tags", {})
            version = dist_tags.get("latest")
            if not version:
                versions = package_info.get("versions", {})
                if versions:
                    version = max(versions.keys())

        if not version:
            return {
                "package": package,
                "error": "Could not determine version",
            }

        logger.info(f"Downloading {package}@{version}")

        # Download tarball
        tarball_data = await download_package_tarball(client, package, version)

        # Check for dependency vulnerabilities
        dep_vulnerabilities = await check_dependency_vulnerabilities(client, package, version)

        # Extract and analyze
        with tempfile.TemporaryDirectory() as tmpdir:
            extract_dir = Path(tmpdir)
            extract_tarball(tarball_data, extract_dir)

            # Find package directory (usually "package" subdirectory)
            package_dir = extract_dir / "package"
            if not package_dir.exists():
                package_dir = extract_dir

            findings = analyze_package_contents(package_dir)
            findings["dependency_vulnerabilities"] = dep_vulnerabilities

            return {
                "package": package,
                "version": version,
                "findings": findings,
            }


async def main():
    """Main entry point."""
    # Replace with your own packages to audit
    packages = [
        "example-package",
    ]

    versions = {
        "example-package": "1.0.0",
    }

    results = []

    for package in packages:
        try:
            version = versions.get(package)
            result = await analyze_package(package, version)
            results.append(result)
        except Exception as e:
            logger.error(f"Error analyzing {package}: {e}")
            results.append(
                {
                    "package": package,
                    "error": str(e),
                }
            )

    # Print results
    print("\n" + "=" * 80)
    print("NPM PACKAGE SECURITY ANALYSIS")
    print("=" * 80 + "\n")

    for result in results:
        if "error" in result:
            print(f"❌ {result['package']}: {result['error']}\n")
            continue

        package = result["package"]
        version = result["version"]
        findings = result["findings"]

        print(f"📦 {package}@{version}")
        print("-" * 80)

        # Secrets found
        secrets = findings["secrets"]
        if secrets:
            print(f"\n🔴 SECRETS FOUND: {len(secrets)}")
            for secret in secrets[:10]:  # Limit to first 10
                print(f"  • {secret['type']} in {secret['file']}:{secret['line']}")
                print(f"    Match: {secret['match']}")
            if len(secrets) > 10:
                print(f"  ... and {len(secrets) - 10} more")
        else:
            print("\n✅ No secrets detected in code")

        # Sensitive files
        sensitive_files = findings["sensitive_files"]
        if sensitive_files:
            print(f"\n🔴 SENSITIVE FILES: {len(sensitive_files)}")
            for file_info in sensitive_files:
                severity_icon = "🔴" if file_info["severity"] == "CRITICAL" else "🟡"
                print(f"  {severity_icon} {file_info['file']} ({file_info['severity']})")
                print(f"    {file_info['description']}")
        else:
            print("\n✅ No sensitive file names detected")

        # Large files
        large_files = findings.get("large_files", [])
        if large_files:
            print(f"\n🟡 LARGE FILES: {len(large_files)}")
            for file_info in large_files:
                print(f"  • {file_info['file']} ({file_info['size_mb']} MB)")
        else:
            print("\n✅ No unusually large files detected")

        # Source maps
        source_maps = findings.get("source_maps", [])
        if source_maps:
            print(f"\n🟡 SOURCE MAPS: {len(source_maps)}")
            for file_info in source_maps[:5]:  # Limit display
                print(f"  • {file_info['file']}")
            if len(source_maps) > 5:
                print(f"  ... and {len(source_maps) - 5} more")

        # Test files with secrets
        test_secrets = findings.get("test_files_with_secrets", [])
        if test_secrets:
            print(f"\n🔴 SECRETS IN TEST FILES: {len(test_secrets)}")
            print("  ⚠️  Test files should not contain real secrets!")
            for secret in test_secrets[:5]:
                print(f"  • {secret['type']} in {secret['file']}:{secret['line']}")

        # Obfuscated code
        obfuscated = findings.get("obfuscated_code", [])
        if obfuscated:
            high_severity = [o for o in obfuscated if o.get("severity") in ["HIGH", "MEDIUM"]]
            if high_severity:
                severity_icon = (
                    "🔴" if any(o.get("severity") == "HIGH" for o in high_severity) else "🟡"
                )
                print(
                    f"\n{severity_icon} OBFUSCATED CODE: {len(obfuscated)} ({len(high_severity)} high/medium severity)"
                )
                print("  ⚠️  Potential code obfuscation detected!")
                for obf in sorted(
                    high_severity,
                    key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x.get("severity"), 3),
                )[:5]:
                    factors = []
                    if obf.get("has_base64_nearby"):
                        factors.append("base64")
                    if obf.get("has_suspicious_vars"):
                        factors.append("suspicious vars")
                    if obf.get("has_hex_strings"):
                        factors.append("hex strings")
                    factors_str = f" ({', '.join(factors)})" if factors else ""
                    print(
                        f"  • [{obf.get('severity', 'UNKNOWN')}] {obf['description']} in {obf['file']}:{obf['line']}{factors_str}"
                    )
            else:
                print(f"\n🟡 OBFUSCATED CODE: {len(obfuscated)} (low severity - likely legitimate)")

        # Git history
        if findings.get("git_history"):
            print("\n🔴 GIT HISTORY DETECTED")
            print("  ⚠️  .git directory found in package - should not be published!")

        # Lock files
        lock_files = findings.get("lock_files", [])
        if lock_files:
            print(f"\n🟡 LOCK FILES: {len(lock_files)}")
            for lock in lock_files:
                print(f"  • {lock['file']}")

        # CI/CD configs
        ci_configs = findings.get("ci_configs", [])
        if ci_configs:
            print(f"\n🟡 CI/CD CONFIGS: {len(ci_configs)}")
            print("  ⚠️  CI/CD configs may contain secrets - review carefully!")
            for ci in ci_configs[:5]:
                print(f"  • {ci['file']}")

        # Missing .npmignore
        if findings.get("npmignore_missing"):
            print("\n🟡 MISSING .npmignore")
            print("  ⚠️  No .npmignore found - ensure sensitive files are excluded")
            print("  💡 Recommendation: Add .npmignore or use 'files' field in package.json")
            print("  💡 Generate one with: uv run python devguard/scripts/generate_npmignore.py")

        # Comments with secrets
        comment_secrets = findings.get("comments_with_secrets", [])
        if comment_secrets:
            print(f"\n🟡 SECRETS IN COMMENTS: {len(comment_secrets)}")
            for comment in comment_secrets[:5]:
                print(f"  • {comment['file']}:{comment['line']}")
                print(f"    {comment['match'][:80]}...")

        # Postinstall scripts
        postinstall_scripts = findings.get("postinstall_scripts", [])
        if postinstall_scripts:
            print(f"\n🟡 INSTALL SCRIPTS: {len(postinstall_scripts)}")
            print("  ⚠️  Install scripts can be security risks - review carefully!")
            for script_info in postinstall_scripts:
                print(f"  • {script_info['script']}: {script_info['content'][:80]}...")

        # Suspicious package names
        suspicious_names = findings.get("suspicious_package_names", [])
        if suspicious_names:
            print(f"\n🟡 SUSPICIOUS PACKAGE NAME PATTERNS: {len(suspicious_names)}")
            for name_issue in suspicious_names:
                print(f"  • {name_issue['reason']}")

        # File permissions
        file_perms = findings.get("file_permissions", [])
        if file_perms:
            print(f"\n🟡 UNUSUAL FILE PERMISSIONS: {len(file_perms)}")
            for perm_issue in file_perms[:5]:
                print(f"  • {perm_issue['file']}: {perm_issue['issue']}")

        # Dependency vulnerabilities
        dep_vulns = findings.get("dependency_vulnerabilities", [])
        if dep_vulns:
            print(f"\n🔴 DEPENDENCY VULNERABILITIES: {len(dep_vulns)}")
            critical_vulns = [v for v in dep_vulns if v.get("severity") in ["CRITICAL", "HIGH"]]
            if critical_vulns:
                print("  ⚠️  Critical/High severity vulnerabilities found!")
                for vuln in critical_vulns[:5]:
                    print(f"  • [{vuln['severity']}] {vuln.get('title', 'Unknown')}")
                    if vuln.get("cve"):
                        print(f"    CVE: {vuln['cve']}")
            else:
                print("  ⚠️  Medium/Low severity vulnerabilities found")
                for vuln in dep_vulns[:5]:
                    print(f"  • [{vuln['severity']}] {vuln.get('title', 'Unknown')[:60]}")

        # Package.json issues
        pkg_issues = findings.get("package_json_issues")
        if pkg_issues:
            if pkg_issues.get("suspicious_scripts"):
                print(f"\n🟡 SUSPICIOUS SCRIPTS: {len(pkg_issues['suspicious_scripts'])}")
                for script in pkg_issues["suspicious_scripts"]:
                    print(f"  • {script['script']}: {script['issue']}")

            if pkg_issues.get("placeholder_values"):
                print(f"\n🟡 PLACEHOLDER VALUES: {len(pkg_issues['placeholder_values'])}")
                for placeholder in pkg_issues["placeholder_values"][:5]:
                    print(f"  • {placeholder['match']}")

            if pkg_issues.get("exposed_repos"):
                print(f"\n🟡 EXPOSED REPOSITORIES: {len(pkg_issues['exposed_repos'])}")
                for repo in pkg_issues["exposed_repos"]:
                    print(f"  • {repo['url']}")

            if pkg_issues.get("files_field_issues"):
                print(f"\n🟡 FILES FIELD ISSUES: {len(pkg_issues['files_field_issues'])}")
                for issue in pkg_issues["files_field_issues"]:
                    print(f"  • {issue}")

            if pkg_issues.get("recommendations"):
                print("\n💡 RECOMMENDATIONS:")
                for rec in pkg_issues["recommendations"]:
                    print(f"  • {rec}")

        # Package.json info
        pkg_json = findings.get("package_json")
        if pkg_json:
            print("\n📄 Package Info:")
            print(f"  Name: {pkg_json.get('name', 'N/A')}")
            print(f"  Version: {pkg_json.get('version', 'N/A')}")
            print(f"  Description: {pkg_json.get('description', 'N/A')[:100]}")

            # Check for scripts that might expose secrets
            scripts = pkg_json.get("scripts", {})
            if scripts:
                print(f"  Scripts: {', '.join(scripts.keys())}")

        print("\n")

    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)

    total_secrets = sum(
        len(r.get("findings", {}).get("secrets", [])) for r in results if "findings" in r
    )
    total_sensitive_files = sum(
        len(r.get("findings", {}).get("sensitive_files", [])) for r in results if "findings" in r
    )
    critical_files = sum(
        1
        for r in results
        if "findings" in r
        for f in r["findings"].get("sensitive_files", [])
        if f.get("severity") == "CRITICAL"
    )
    test_secrets = sum(
        len(r.get("findings", {}).get("test_files_with_secrets", []))
        for r in results
        if "findings" in r
    )
    obfuscated_count = sum(
        len(r.get("findings", {}).get("obfuscated_code", [])) for r in results if "findings" in r
    )
    git_history_count = sum(1 for r in results if r.get("findings", {}).get("git_history"))
    lock_files_count = sum(
        len(r.get("findings", {}).get("lock_files", [])) for r in results if "findings" in r
    )
    ci_configs_count = sum(
        len(r.get("findings", {}).get("ci_configs", [])) for r in results if "findings" in r
    )
    comment_secrets_count = sum(
        len(r.get("findings", {}).get("comments_with_secrets", []))
        for r in results
        if "findings" in r
    )
    dep_vuln_count = sum(
        len(r.get("findings", {}).get("dependency_vulnerabilities", []))
        for r in results
        if "findings" in r
    )
    critical_dep_vulns = sum(
        1
        for r in results
        if "findings" in r
        for v in r["findings"].get("dependency_vulnerabilities", [])
        if v.get("severity") in ["CRITICAL", "HIGH"]
    )

    print(f"Total packages analyzed: {len(packages)}")
    print(f"Total secrets found: {total_secrets}")
    print(f"Total sensitive files: {total_sensitive_files}")
    print(f"Critical files (with secrets): {critical_files}")
    print(f"Secrets in test files: {test_secrets}")
    print(f"Obfuscated code patterns: {obfuscated_count}")
    print(f"Packages with git history: {git_history_count}")
    print(f"Lock files published: {lock_files_count}")
    print(f"CI/CD configs: {ci_configs_count}")
    print(f"Secrets in comments: {comment_secrets_count}")
    print(f"Dependency vulnerabilities: {dep_vuln_count}")
    print(f"Critical/High dep vulnerabilities: {critical_dep_vulns}")

    if total_secrets > 0 or critical_files > 0 or test_secrets > 0 or critical_dep_vulns > 0:
        print(
            "\n🔴 ACTION REQUIRED: Review findings above and remove any exposed secrets or fix vulnerabilities!"
        )
    elif total_sensitive_files > 0:
        print(
            "\n🟡 REVIEW RECOMMENDED: Some sensitive file names detected (may be false positives)"
        )
    else:
        print("\n✅ No obvious security issues detected")

    # Additional recommendations
    missing_npmignore = sum(1 for r in results if r.get("findings", {}).get("npmignore_missing"))
    if missing_npmignore > 0:
        print(f"\n💡 RECOMMENDATION: {missing_npmignore} package(s) missing .npmignore")
        print("   Consider generating .npmignore files for better security")
        print("   Run: uv run python devguard/scripts/generate_npmignore.py")

    if obfuscated_count > 0:
        print(f"\n💡 RECOMMENDATION: Review {obfuscated_count} obfuscated code patterns")
        print("   Ensure they are legitimate uses (e.g., base64 encoding for data, not secrets)")

    if dep_vuln_count > 0:
        print(f"\n💡 RECOMMENDATION: {dep_vuln_count} dependency vulnerabilities found")
        print("   Run 'npm audit' or update vulnerable dependencies")
        if critical_dep_vulns > 0:
            print(f"   ⚠️  {critical_dep_vulns} CRITICAL/HIGH severity - prioritize fixing!")

    print(
        "\n💡 Generate detailed JSON report: uv run python devguard/scripts/generate_security_report.py"
    )
    print(
        "💡 Get automated fix recommendations: uv run python devguard/scripts/auto_fix_recommendations.py"
    )


if __name__ == "__main__":
    asyncio.run(main())
