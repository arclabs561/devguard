"""SSH key hygiene audit sweep: detect weak, unprotected, or stale SSH keys.

Scans ~/.ssh/ for private key files and checks:
- Algorithm type and bit strength (flags DSA, short RSA, optionally ECDSA)
- Passphrase protection (keys without a passphrase are flagged)
- File permissions (should be 600 or 400)
- GitHub registration (cross-references with `gh ssh-key list`)
"""

from __future__ import annotations

import json
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

from devguard.sweeps._common import utc_now as _utc_now


# Well-known private key filenames (without path).
_WELL_KNOWN_NAMES = {"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"}

# PEM header that marks a private key file.
_PRIVATE_KEY_HEADER = b"-----BEGIN"


def _is_private_key_file(path: Path) -> bool:
    """Heuristic: file looks like an SSH private key."""
    if not path.is_file():
        return False
    # Skip .pub files
    if path.suffix == ".pub":
        return False
    # Well-known names are always candidates
    if path.name in _WELL_KNOWN_NAMES:
        return True
    # Otherwise check for PEM header in first 64 bytes
    try:
        head = path.read_bytes()[:64]
        return _PRIVATE_KEY_HEADER in head
    except (OSError, PermissionError):
        return False


def _parse_keygen_fingerprint(output: str) -> tuple[int, str, str]:
    """Parse `ssh-keygen -l` output into (bits, fingerprint, key_type).

    Example lines:
        256 SHA256:abc...xyz user@host (ED25519)
        3072 SHA256:def...uvw user@host (RSA)
    """
    # Pattern: <bits> <fingerprint> <comment> (<type>)
    m = re.match(r"(\d+)\s+(SHA256:\S+).*\((\w+)\)", output.strip())
    if m:
        return int(m.group(1)), m.group(2), m.group(3).upper()
    return 0, "", "UNKNOWN"


def _get_key_info(key_path: Path) -> tuple[int, str, str, list[str]]:
    """Run ssh-keygen -l to get bits, fingerprint, type. Returns (bits, fingerprint, algo, errors)."""
    errors: list[str] = []
    if not shutil.which("ssh-keygen"):
        return 0, "", "UNKNOWN", ["ssh-keygen not found on PATH"]
    try:
        res = subprocess.run(
            ["ssh-keygen", "-l", "-f", str(key_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode != 0:
            errors.append(f"ssh-keygen -l failed: {res.stderr.strip()}")
            return 0, "", "UNKNOWN", errors
        bits, fingerprint, algo = _parse_keygen_fingerprint(res.stdout)
        return bits, fingerprint, algo, errors
    except subprocess.TimeoutExpired:
        return 0, "", "UNKNOWN", ["ssh-keygen -l timed out"]
    except OSError as exc:
        return 0, "", "UNKNOWN", [f"ssh-keygen -l error: {exc}"]


def _check_passphrase(key_path: Path) -> tuple[bool | None, list[str]]:
    """Check whether a private key has a passphrase.

    Returns (has_passphrase, errors).
    - True  = passphrase-protected (good)
    - False = no passphrase (bad)
    - None  = could not determine
    """
    errors: list[str] = []
    if not shutil.which("ssh-keygen"):
        return None, ["ssh-keygen not found on PATH"]
    try:
        res = subprocess.run(
            ["ssh-keygen", "-y", "-P", "", "-f", str(key_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # Exit 0 + public key on stdout => no passphrase (bad)
        if res.returncode == 0:
            return False, errors
        # Non-zero => passphrase required (good) or other error
        stderr = res.stderr.strip().lower()
        if "incorrect passphrase" in stderr or "bad passphrase" in stderr:
            return True, errors
        # Some other failure (corrupt key, permission issue, etc.)
        return None, [f"passphrase check inconclusive: {res.stderr.strip()}"]
    except subprocess.TimeoutExpired:
        return None, ["passphrase check timed out"]
    except OSError as exc:
        return None, [f"passphrase check error: {exc}"]


def _check_permissions(key_path: Path) -> tuple[bool, str]:
    """Check file permissions. Returns (ok, octal_string)."""
    try:
        mode = key_path.stat().st_mode
        file_perms = stat.S_IMODE(mode)
        octal_str = f"{file_perms:04o}"
        # Acceptable: 0600 (owner rw) or 0400 (owner r)
        ok = file_perms in (0o600, 0o400)
        return ok, octal_str
    except OSError:
        return False, "????"


def _get_github_keys() -> tuple[list[dict[str, str]], list[str]]:
    """Fetch SSH keys registered on GitHub via `gh ssh-key list`.

    Returns (keys, errors) where each key is {"fingerprint": ..., "title": ...}.
    """
    errors: list[str] = []
    if not shutil.which("gh"):
        return [], ["gh CLI not found on PATH; skipping GitHub cross-reference"]
    try:
        res = subprocess.run(
            ["gh", "ssh-key", "list"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if res.returncode != 0:
            stderr = res.stderr.strip()
            return [], [f"gh ssh-key list failed: {stderr}"]
    except subprocess.TimeoutExpired:
        return [], ["gh ssh-key list timed out"]
    except OSError as exc:
        return [], [f"gh ssh-key list error: {exc}"]

    keys: list[dict[str, str]] = []
    for line in res.stdout.strip().splitlines():
        # Format: TITLE\tTYPE\tFINGERPRINT\tADDED
        # or:     TITLE\tFINGERPRINT\tADDED  (older gh versions)
        parts = line.split("\t")
        if len(parts) >= 3:
            title = parts[0].strip()
            # Fingerprint is the part that starts with SHA256:
            fingerprint = ""
            for p in parts[1:]:
                p = p.strip()
                if p.startswith("SHA256:"):
                    fingerprint = p
                    break
            if fingerprint:
                keys.append({"title": title, "fingerprint": fingerprint})
    return keys, errors


def audit_ssh_keys(
    *,
    ssh_dir: Path | None = None,
    check_github: bool = True,
    min_rsa_bits: int = 3072,
    flag_ecdsa: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    """Audit SSH keys and return (report, errors)."""
    errors: list[str] = []
    ssh_path = ssh_dir if ssh_dir is not None else Path("~/.ssh").expanduser()

    if not ssh_path.is_dir():
        report: dict[str, Any] = {
            "generated_at": _utc_now(),
            "scope": {"ssh_dir": str(ssh_path)},
            "summary": {"keys_scanned": 0, "issues_total": 0},
            "keys": [],
            "github_cross_reference": None,
            "errors": [f"SSH directory not found: {ssh_path}"],
        }
        return report, [f"SSH directory not found: {ssh_path}"]

    # Discover private key files
    private_keys: list[Path] = []
    try:
        for entry in sorted(ssh_path.iterdir()):
            if _is_private_key_file(entry):
                private_keys.append(entry)
    except PermissionError as exc:
        errors.append(f"cannot read {ssh_path}: {exc}")

    # Analyze each key
    key_results: list[dict[str, Any]] = []
    local_fingerprints: dict[str, str] = {}  # fingerprint -> key_path

    for key_path in private_keys:
        issues: list[str] = []

        # Algorithm and bit strength
        bits, fingerprint, algo, key_errors = _get_key_info(key_path)
        errors.extend(key_errors)

        if fingerprint:
            local_fingerprints[fingerprint] = str(key_path)

        # Weak algorithm checks
        if algo == "DSA":
            issues.append("DSA algorithm is deprecated and weak")
        elif algo == "RSA" and bits > 0 and bits < min_rsa_bits:
            issues.append(f"RSA key is {bits}-bit (minimum recommended: {min_rsa_bits})")
        elif algo == "ECDSA" and flag_ecdsa:
            issues.append("ECDSA uses NIST curves (flagged by policy)")

        # Passphrase check
        has_passphrase, pp_errors = _check_passphrase(key_path)
        errors.extend(pp_errors)
        if has_passphrase is False:
            issues.append("no passphrase protection")

        # Permissions check
        perms_ok, perms_octal = _check_permissions(key_path)
        if not perms_ok:
            issues.append(f"permissions too open: {perms_octal} (should be 0600 or 0400)")

        key_results.append({
            "key_path": str(key_path),
            "algorithm": algo,
            "bits": bits,
            "fingerprint": fingerprint,
            "has_passphrase": has_passphrase,
            "permissions": perms_octal,
            "permissions_ok": perms_ok,
            "issues": issues,
        })

    # GitHub cross-reference
    github_cross_ref: dict[str, Any] | None = None
    if check_github:
        gh_keys, gh_errors = _get_github_keys()
        errors.extend(gh_errors)

        if gh_keys or not gh_errors:
            gh_fingerprints = {k["fingerprint"] for k in gh_keys}
            local_fp_set = set(local_fingerprints.keys())

            local_not_on_github = [
                {"fingerprint": fp, "key_path": local_fingerprints[fp]}
                for fp in sorted(local_fp_set - gh_fingerprints)
            ]
            github_not_local = [
                {"fingerprint": k["fingerprint"], "title": k["title"]}
                for k in gh_keys
                if k["fingerprint"] not in local_fp_set
            ]

            github_cross_ref = {
                "github_keys_count": len(gh_keys),
                "local_not_on_github": local_not_on_github,
                "github_not_local": github_not_local,
            }

            # Add cross-ref issues to relevant keys
            for entry in local_not_on_github:
                for kr in key_results:
                    if kr["fingerprint"] == entry["fingerprint"]:
                        kr["registered_on_github"] = False
                        kr["issues"].append("not registered on GitHub (stale?)")

            # Mark keys that are registered
            for kr in key_results:
                if "registered_on_github" not in kr:
                    if kr["fingerprint"] and kr["fingerprint"] in gh_fingerprints:
                        kr["registered_on_github"] = True
                    elif not kr["fingerprint"]:
                        kr["registered_on_github"] = None
                    else:
                        kr["registered_on_github"] = False

    total_issues = sum(len(k["issues"]) for k in key_results)

    report = {
        "generated_at": _utc_now(),
        "scope": {
            "ssh_dir": str(ssh_path),
            "check_github": check_github,
            "min_rsa_bits": min_rsa_bits,
            "flag_ecdsa": flag_ecdsa,
        },
        "summary": {
            "keys_scanned": len(key_results),
            "issues_total": total_issues,
            "keys_without_passphrase": sum(
                1 for k in key_results if k["has_passphrase"] is False
            ),
            "keys_with_weak_algorithm": sum(
                1 for k in key_results
                if any("deprecated" in i or "bit" in i or "NIST" in i for i in k["issues"])
            ),
            "keys_with_bad_permissions": sum(
                1 for k in key_results if not k["permissions_ok"]
            ),
        },
        "keys": key_results,
        "github_cross_reference": github_cross_ref,
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
