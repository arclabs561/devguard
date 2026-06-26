"""Public-repo design/ADR doc-tracking checker.

Flags repos that track files under `docs/design/` or `docs/adr/`, or whose
`.gitignore` re-includes that namespace (`!docs/adr/`, `!docs/design/`), while
the repo is public.

This is for workspaces whose convention keeps design and ADR notes local-only
(globally gitignored) as private working scratch, and surfaces a public record
in a normal tracked doc outside that namespace instead. It is **opt-in**
(disabled by default), because many projects deliberately publish their ADRs
and would not want this flagged.

Local-first: the candidate filter (tracked files / opt-in line) is pure local
git, so visibility -- the only network call, via `gh` -- is resolved ONLY for
repos that are already candidates, which is typically zero.
"""

import logging
import os
import re
import subprocess
from pathlib import Path

from devguard.checkers.base import BaseChecker
from devguard.models import CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

DOC_DIRS = ("docs/design", "docs/adr")
OPTIN_PATTERNS = ("!docs/adr/", "!docs/design/")


class PrivateDocsChecker(BaseChecker):
    """Flag public repos that track the design/adr doc namespace."""

    check_type = "private_docs"

    async def check(self) -> CheckResult:
        """Scan workspace repos; flag public ones tracking design/adr docs."""
        findings: list[Finding] = []
        errors: list[str] = []
        candidates: list[str] = []

        for repo in self._get_repos_to_scan():
            try:
                tracked = self._tracked_doc_files(repo)
                optin = self._gitignore_optin(repo)
                if not tracked and not optin:
                    continue  # nothing in the namespace is tracked here
                candidates.append(str(repo))

                if not self._repo_slug(repo):
                    continue  # no remote: local-only, cannot be publicly exposed
                visibility = self._repo_visibility(repo)
                if visibility == "private":
                    continue  # only public exposure is in scope

                reasons = []
                if tracked:
                    dirs = sorted({"/".join(p.split("/")[:2]) for p in tracked})
                    reasons.append(f"{len(tracked)} tracked file(s) under {', '.join(dirs)}")
                if optin:
                    reasons.append(f".gitignore re-includes: {', '.join(optin)}")

                public = visibility == "public"
                findings.append(
                    Finding(
                        severity=Severity.HIGH if public else Severity.WARNING,
                        title=(
                            "Public repo tracks design/adr docs"
                            if public
                            else "Repo tracks design/adr docs; visibility unknown"
                        ),
                        description=(
                            f"{repo.name}: {'; '.join(reasons)}. The design/adr namespace is "
                            "configured as local-only working scratch for this workspace, so "
                            "tracking it in a public repo can expose internal notes."
                        ),
                        resource=str(repo),
                        remediation=(
                            "git rm -r --cached docs/design docs/adr (keeps local copies); "
                            "remove any !docs/adr/ or !docs/design/ re-include from .gitignore; "
                            "move any intended-public record to a normal tracked doc outside "
                            "the design/adr namespace."
                        ),
                        metadata={
                            "visibility": visibility or "unknown",
                            "tracked": tracked,
                            "optin": optin,
                        },
                    )
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{repo}: {exc}")

        return CheckResult(
            check_type=self.check_type,
            success=len(findings) == 0,
            findings=findings,
            errors=errors,
            metadata={"candidates": candidates},
        )

    # --- helpers (each small and independently testable) ---

    def _tracked_doc_files(self, repo: Path) -> list[str]:
        out = self._git(repo, ["ls-files", *DOC_DIRS])
        return [line for line in out.splitlines() if line.strip()]

    def _gitignore_optin(self, repo: Path) -> list[str]:
        gitignore = repo / ".gitignore"
        if not gitignore.is_file():
            return []
        hits: set[str] = set()
        for raw in gitignore.read_text(errors="ignore").splitlines():
            line = raw.strip()
            for pat in OPTIN_PATTERNS:
                if line == pat or line == pat.rstrip("/"):
                    hits.add(pat)
        return sorted(hits)

    def _repo_visibility(self, repo: Path) -> str | None:
        """Return 'public' | 'private' | None (when it can't be determined)."""
        slug = self._repo_slug(repo)
        if not slug:
            return None
        try:
            # Empty GITHUB_TOKEN forces the keyring credential (fork-PAT fallback).
            result = subprocess.run(
                ["gh", "repo", "view", slug, "--json", "visibility", "-q", ".visibility"],
                cwd=str(repo),
                capture_output=True,
                text=True,
                timeout=15,
                env={**os.environ, "GITHUB_TOKEN": ""},
                check=False,
            )
            value = result.stdout.strip().lower()
            return value if value in ("public", "private") else None
        except Exception:  # noqa: BLE001
            return None

    def _repo_slug(self, repo: Path) -> str | None:
        url = self._git(repo, ["remote", "get-url", "origin"]).strip()
        match = re.search(r"[:/]([^/]+/[^/]+?)(?:\.git)?/?$", url)
        return match.group(1) if match else None

    def _git(self, repo: Path, args: list[str]) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", str(repo), *args],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            return result.stdout
        except Exception:  # noqa: BLE001
            return ""

    def _get_repos_to_scan(self) -> list[Path]:
        """Enumerate sibling git repos in the workspace (or a configured root)."""
        root_setting = getattr(self.settings, "private_docs_scan_root", None)
        if root_setting:
            root = Path(root_setting).expanduser()
        else:
            cur = Path.cwd().resolve()
            git_root = next((p for p in [cur, *cur.parents] if (p / ".git").exists()), None)
            root = git_root.parent if git_root else cur

        repos: list[Path] = []
        if root.is_dir():
            for git_path in sorted(root.glob("*/.git")):
                repos.append(git_path.parent)
        return repos
