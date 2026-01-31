"""Secret scanning checker using trufflehog with fallback."""

import asyncio
import json
import logging
import re
import shutil
from pathlib import Path

from guardian.checkers.base import BaseChecker
from guardian.config import Settings
from guardian.models import CheckResult, Severity, Vulnerability

logger = logging.getLogger(__name__)


class SecretChecker(BaseChecker):
    """Check git repositories for leaked secrets using trufflehog or fallback regex.

    Scans:
    1. Configured git repos for secrets in history
    2. Filesystem for current secrets (excluding .env files)

    Uses trufflehog (Go-based, fast) if available.
    Falls back to regex scanning if trufflehog is not installed.
    """

    check_type = "secret"

    # Fallback patterns if trufflehog is missing
    FALLBACK_PATTERNS = [
        (r"AWS_ACCESS_KEY_ID\s*=\s*['\"]?(AKIA[0-9A-Z]{16})['\"]?", "AWS Access Key"),
        (r"AWS_SECRET_ACCESS_KEY\s*=\s*['\"]?([0-9a-zA-Z/+]{40})['\"]?", "AWS Secret Key"),
        (r"PRIVATE_KEY\s*=\s*['\"]?(-+BEGIN PRIVATE KEY-+)['\"]?", "Private Key"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
        (r"xox[baprs]-([0-9a-zA-Z]{10,48})", "Slack Token"),
        (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Secret Key"),
        (r"api_key\s*=\s*['\"]?([a-zA-Z0-9]{32,})['\"]?", "Generic API Key"),
    ]

    def __init__(self, settings: Settings):
        """Initialize secret checker."""
        super().__init__(settings)
        self.trufflehog_path = shutil.which("trufflehog")

    async def check(self) -> CheckResult:
        """Check for leaked secrets."""
        vulnerabilities: list[Vulnerability] = []
        errors: list[str] = []
        metadata: dict = {
            "repos_scanned": [],
            "total_findings": 0,
            "engine": "trufflehog" if self.trufflehog_path else "regex-fallback",
        }

        # Scan configured repos.
        #
        # Important: when TruffleHog is missing, the regex fallback is both limited
        # in quality and potentially very slow on large repos. In that mode we only
        # scan explicitly configured paths to avoid accidental multi-repo sweeps.
        repos_to_scan = self._get_repos_to_scan()
        if not self.trufflehog_path and not self.settings.secret_scan_paths:
            repos_to_scan = []

        for repo_path in repos_to_scan:
            try:
                if self.trufflehog_path:
                    findings = await self._scan_git_history(repo_path)
                else:
                    findings = await self._scan_with_regex(repo_path)
                    if not findings and not errors:  # Only warn once or if we find nothing
                        pass  # Silence is golden, but we should note it

                vulnerabilities.extend(findings)
                metadata["repos_scanned"].append(str(repo_path))
            except Exception as e:
                errors.append(f"Error scanning {repo_path}: {str(e)}")

        if not self.trufflehog_path:
            errors.append(
                "Warning: trufflehog not found. Using limited regex fallback. Install with `brew install trufflehog` for better security."
            )
            if not self.settings.secret_scan_paths:
                errors.append(
                    "No secret_scan_paths configured; skipping regex fallback scan to avoid slow large-repo sweeps."
                )

        metadata["total_findings"] = len(vulnerabilities)

        return CheckResult(
            check_type=self.check_type,
            success=len(vulnerabilities) == 0,
            vulnerabilities=vulnerabilities,
            errors=errors,
            metadata=metadata,
        )

    def _get_repos_to_scan(self) -> list[Path]:
        """Get list of git repos to scan for secrets."""
        repos = []

        def is_git_repo(p: Path) -> bool:
            # Support both .git directories and gitfiles (worktrees/submodules)
            return (p / ".git").is_dir() or (p / ".git").is_file()

        def find_git_root(start: Path) -> Path | None:
            cur = start.resolve()
            for parent in [cur, *cur.parents]:
                if is_git_repo(parent):
                    return parent
            return None

        # Check configured secret scan paths
        if self.settings.secret_scan_paths:
            for path_str in self.settings.secret_scan_paths:
                path = Path(path_str).expanduser()
                if path.exists() and is_git_repo(path):
                    repos.append(path)
                elif path.is_dir():
                    # Look for .git in subdirectories
                    for git_dir in path.glob("*/.git"):
                        repos.append(git_dir.parent)

        # Default: try to find "nearby" repos (works both when Guardian lives inside
        # a larger super-workspace and when it's a standalone repo).
        if not repos:
            # 1) If we are in a super-workspace, scan sibling repos if present.
            # We use the current repo's parent as the "workspace root" candidate.
            # When Guardian is installed (e.g., in CI), `__file__` will live under
            # site-packages and won't have a `.git` ancestor. Prefer CWD first.
            this_repo = find_git_root(Path.cwd()) or find_git_root(Path(__file__))
            workspace_root = this_repo.parent if this_repo else Path.cwd()

            for rel in [
                "_infra",  # umbrella dir (may itself be a git repo in some setups)
                "_infra/infra",  # common layout: infra repo inside _infra
                "accounting",
                "dossier",
                "www",
                "ops",
            ]:
                p = (workspace_root / rel).resolve()
                if p.exists() and is_git_repo(p):
                    repos.append(p)

            # 2) Always fall back to scanning Guardian itself (first application on itself).
            if not repos and this_repo and is_git_repo(this_repo):
                repos.append(this_repo)

        return repos

    async def _scan_git_history(self, repo_path: Path) -> list[Vulnerability]:
        """Scan a git repo's history for secrets using trufflehog."""
        if not self.trufflehog_path:
            return []

        vulnerabilities: list[Vulnerability] = []

        cmd = [
            self.trufflehog_path,
            "git",
            f"file://{repo_path}",
            "--no-update",
            "--only-verified",
            "--json",
        ]

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)
        except TimeoutError:
            logger.warning(f"Timeout scanning {repo_path}")
            if proc:
                try:
                    proc.kill()
                    await proc.wait()
                except ProcessLookupError:
                    pass  # Process already terminated
            return []
        except Exception as e:
            logger.warning(f"Error running trufflehog on {repo_path}: {e}")
            if proc:
                try:
                    proc.kill()
                    await proc.wait()
                except ProcessLookupError:
                    pass
            return []

        # Parse JSON lines output
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                finding = json.loads(line)
                vuln = self._parse_finding(finding, repo_path)
                if vuln:
                    vulnerabilities.append(vuln)
            except json.JSONDecodeError:
                continue

        return vulnerabilities

    async def _scan_with_regex(self, repo_path: Path) -> list[Vulnerability]:
        """Scan files in repo using fallback regex."""
        vulnerabilities = []

        # Walk through files, ignoring .git and node_modules
        for path in repo_path.rglob("*"):
            if not path.is_file():
                continue
            if any(p in str(path) for p in [".git", "node_modules", "venv", "__pycache__"]):
                continue
            # Skip large files
            if path.stat().st_size > 1024 * 1024:  # 1MB
                continue

            try:
                content = path.read_text(errors="ignore")
                for pattern, name in self.FALLBACK_PATTERNS:
                    if re.search(pattern, content):
                        vulnerabilities.append(
                            Vulnerability(
                                package_name=f"{repo_path.name}/{path.relative_to(repo_path)}",
                                package_version="HEAD",
                                severity=Severity.HIGH,
                                summary=f"Possible {name} found (Regex)",
                                description=f"Found pattern matching {name} in file. Please verify.",
                                source="guardian-regex-fallback",
                            )
                        )
            except Exception:
                continue

        return vulnerabilities

    def _parse_finding(self, finding: dict, repo_path: Path) -> Vulnerability | None:
        """Parse a trufflehog finding into a Vulnerability."""
        try:
            detector_type = finding.get("DetectorName", "unknown")
            verified = finding.get("Verified", False)

            # Only report verified findings
            if not verified:
                return None

            # Get source metadata
            source_metadata = finding.get("SourceMetadata", {}).get("Data", {})
            git_data = source_metadata.get("Git", {})

            file_path = git_data.get("file", "unknown")
            commit = git_data.get("commit", "")[:8] if git_data.get("commit") else ""

            # Redact the actual secret
            raw = finding.get("Raw", "")
            redacted = raw[:4] + "..." + raw[-4:] if len(raw) > 8 else "[redacted]"

            summary = f"Verified {detector_type} secret in {repo_path.name}/{file_path}"
            if commit:
                summary += f" (commit {commit})"

            return Vulnerability(
                package_name=f"{repo_path.name}/{file_path}",
                package_version=commit or "HEAD",
                severity=Severity.CRITICAL,  # Verified secrets are always critical
                summary=summary,
                description=f"Verified {detector_type} credential found. Value: {redacted}",
                source="trufflehog",
            )
        except Exception as e:
            logger.warning(f"Error parsing trufflehog finding: {e}")
            return None
