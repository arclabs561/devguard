"""Tests for SSH key audit sweep."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from guardian.sweeps.ssh_key_audit import (
    _check_passphrase,
    _check_permissions,
    _is_private_key_file,
    _parse_keygen_fingerprint,
    audit_ssh_keys,
)

# ---------------------------------------------------------------------------
# _parse_keygen_fingerprint
# ---------------------------------------------------------------------------


def test_parse_fingerprint_ed25519() -> None:
    line = "256 SHA256:abcdefghijklmnopqrstuvwxyz012345678901234 user@host (ED25519)"
    bits, fp, algo = _parse_keygen_fingerprint(line)
    assert bits == 256
    assert fp.startswith("SHA256:")
    assert algo == "ED25519"


def test_parse_fingerprint_rsa() -> None:
    line = "3072 SHA256:RSAkeyfingerprint1234567890abcdefghijklm user@host (RSA)"
    bits, fp, algo = _parse_keygen_fingerprint(line)
    assert bits == 3072
    assert algo == "RSA"


def test_parse_fingerprint_dsa() -> None:
    line = "1024 SHA256:DSAkeyfingerprint1234567890abcdefghijklm user@host (DSA)"
    bits, fp, algo = _parse_keygen_fingerprint(line)
    assert bits == 1024
    assert algo == "DSA"


def test_parse_fingerprint_ecdsa() -> None:
    line = "256 SHA256:ECDSAfp1234567890abcdefghijklmnopqrstuvw user@host (ECDSA)"
    bits, fp, algo = _parse_keygen_fingerprint(line)
    assert bits == 256
    assert algo == "ECDSA"


def test_parse_fingerprint_garbage() -> None:
    bits, fp, algo = _parse_keygen_fingerprint("not a valid line")
    assert bits == 0
    assert fp == ""
    assert algo == "UNKNOWN"


# ---------------------------------------------------------------------------
# _is_private_key_file
# ---------------------------------------------------------------------------


def test_is_private_key_wellknown(tmp_path: Path) -> None:
    key = tmp_path / "id_ed25519"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n")
    assert _is_private_key_file(key) is True


def test_is_private_key_pub_excluded(tmp_path: Path) -> None:
    pub = tmp_path / "id_ed25519.pub"
    pub.write_text("ssh-ed25519 AAAA... user@host")
    assert _is_private_key_file(pub) is False


def test_is_private_key_by_header(tmp_path: Path) -> None:
    key = tmp_path / "my_custom_key"
    key.write_bytes(b"-----BEGIN RSA PRIVATE KEY-----\nfake\n")
    assert _is_private_key_file(key) is True


def test_is_private_key_not_a_key(tmp_path: Path) -> None:
    f = tmp_path / "config"
    f.write_text("Host *\n  ForwardAgent no\n")
    assert _is_private_key_file(f) is False


# ---------------------------------------------------------------------------
# _check_permissions
# ---------------------------------------------------------------------------


def test_permissions_600(tmp_path: Path) -> None:
    key = tmp_path / "id_test"
    key.write_text("fake key")
    key.chmod(0o600)
    ok, octal = _check_permissions(key)
    assert ok is True
    assert octal == "0600"


def test_permissions_400(tmp_path: Path) -> None:
    key = tmp_path / "id_test"
    key.write_text("fake key")
    key.chmod(0o400)
    ok, octal = _check_permissions(key)
    assert ok is True
    assert octal == "0400"


def test_permissions_644_bad(tmp_path: Path) -> None:
    key = tmp_path / "id_test"
    key.write_text("fake key")
    key.chmod(0o644)
    ok, octal = _check_permissions(key)
    assert ok is False
    assert octal == "0644"


def test_permissions_755_bad(tmp_path: Path) -> None:
    key = tmp_path / "id_test"
    key.write_text("fake key")
    key.chmod(0o755)
    ok, octal = _check_permissions(key)
    assert ok is False
    assert octal == "0755"


# ---------------------------------------------------------------------------
# _check_passphrase (mocked subprocess)
# ---------------------------------------------------------------------------


def test_passphrase_no_passphrase(tmp_path: Path) -> None:
    """Key without passphrase: ssh-keygen -y -P '' exits 0."""
    key = tmp_path / "id_test"
    key.write_text("fake")

    result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="ssh-ed25519 AAAA...\n", stderr=""
    )
    with patch("guardian.sweeps.ssh_key_audit.subprocess.run", return_value=result):
        with patch("guardian.sweeps.ssh_key_audit.shutil.which", return_value="/usr/bin/ssh-keygen"):
            has_pp, errors = _check_passphrase(key)
    assert has_pp is False
    assert errors == []


def test_passphrase_has_passphrase(tmp_path: Path) -> None:
    """Key with passphrase: ssh-keygen -y -P '' exits non-zero with 'incorrect passphrase'."""
    key = tmp_path / "id_test"
    key.write_text("fake")

    result = subprocess.CompletedProcess(
        args=[], returncode=255, stdout="", stderr="incorrect passphrase supplied to decrypt private key"
    )
    with patch("guardian.sweeps.ssh_key_audit.subprocess.run", return_value=result):
        with patch("guardian.sweeps.ssh_key_audit.shutil.which", return_value="/usr/bin/ssh-keygen"):
            has_pp, errors = _check_passphrase(key)
    assert has_pp is True
    assert errors == []


def test_passphrase_bad_passphrase_message(tmp_path: Path) -> None:
    """Older OpenSSH uses 'bad passphrase' wording."""
    key = tmp_path / "id_test"
    key.write_text("fake")

    result = subprocess.CompletedProcess(
        args=[], returncode=255, stdout="", stderr="bad passphrase"
    )
    with patch("guardian.sweeps.ssh_key_audit.subprocess.run", return_value=result):
        with patch("guardian.sweeps.ssh_key_audit.shutil.which", return_value="/usr/bin/ssh-keygen"):
            has_pp, errors = _check_passphrase(key)
    assert has_pp is True


def test_passphrase_ssh_keygen_missing(tmp_path: Path) -> None:
    key = tmp_path / "id_test"
    key.write_text("fake")

    with patch("guardian.sweeps.ssh_key_audit.shutil.which", return_value=None):
        has_pp, errors = _check_passphrase(key)
    assert has_pp is None
    assert any("not found" in e for e in errors)


# ---------------------------------------------------------------------------
# audit_ssh_keys (end-to-end with mocked subprocess)
# ---------------------------------------------------------------------------


def test_audit_ssh_keys_missing_dir(tmp_path: Path) -> None:
    """Non-existent SSH dir produces empty report with error."""
    missing = tmp_path / "nosshdir"
    report, errors = audit_ssh_keys(ssh_dir=missing, check_github=False)
    assert report["summary"]["keys_scanned"] == 0
    assert len(errors) > 0
    assert "not found" in errors[0]


def test_audit_ssh_keys_basic(tmp_path: Path) -> None:
    """End-to-end with a fake key directory, mocked ssh-keygen and no gh."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()

    # Create a fake private key
    key = ssh_dir / "id_ed25519"
    key.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n")
    key.chmod(0o600)

    # Create a .pub file (should be skipped)
    pub = ssh_dir / "id_ed25519.pub"
    pub.write_text("ssh-ed25519 AAAA... user@host")

    # Create a config file (should be skipped)
    cfg = ssh_dir / "config"
    cfg.write_text("Host *\n  ForwardAgent no\n")

    keygen_l_result = subprocess.CompletedProcess(
        args=[], returncode=0,
        stdout="256 SHA256:testfp1234567890abcdefghijklmnopqrstuvw user@host (ED25519)",
        stderr="",
    )
    keygen_y_result = subprocess.CompletedProcess(
        args=[], returncode=0,
        stdout="ssh-ed25519 AAAA...\n",
        stderr="",
    )

    def mock_run(cmd, **kwargs):
        if cmd[1] == "-l":
            return keygen_l_result
        if cmd[1] == "-y":
            return keygen_y_result
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")

    with patch("guardian.sweeps.ssh_key_audit.subprocess.run", side_effect=mock_run):
        with patch("guardian.sweeps.ssh_key_audit.shutil.which", return_value="/usr/bin/ssh-keygen"):
            report, errors = audit_ssh_keys(ssh_dir=ssh_dir, check_github=False)

    assert report["summary"]["keys_scanned"] == 1
    kr = report["keys"][0]
    assert kr["algorithm"] == "ED25519"
    assert kr["bits"] == 256
    assert kr["permissions_ok"] is True
    # No passphrase (exit 0 from mock)
    assert kr["has_passphrase"] is False
    assert "no passphrase protection" in kr["issues"]


def test_audit_ssh_keys_weak_rsa(tmp_path: Path) -> None:
    """RSA key below min_rsa_bits is flagged."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()

    key = ssh_dir / "id_rsa"
    key.write_bytes(b"-----BEGIN RSA PRIVATE KEY-----\nfake\n")
    key.chmod(0o600)

    keygen_l_result = subprocess.CompletedProcess(
        args=[], returncode=0,
        stdout="2048 SHA256:rsafp1234567890abcdefghijklmnopqrstuvwxy user@host (RSA)",
        stderr="",
    )
    keygen_y_result = subprocess.CompletedProcess(
        args=[], returncode=255, stdout="",
        stderr="incorrect passphrase supplied to decrypt private key",
    )

    def mock_run(cmd, **kwargs):
        if cmd[1] == "-l":
            return keygen_l_result
        if cmd[1] == "-y":
            return keygen_y_result
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")

    with patch("guardian.sweeps.ssh_key_audit.subprocess.run", side_effect=mock_run):
        with patch("guardian.sweeps.ssh_key_audit.shutil.which", return_value="/usr/bin/ssh-keygen"):
            report, _ = audit_ssh_keys(ssh_dir=ssh_dir, check_github=False, min_rsa_bits=3072)

    kr = report["keys"][0]
    assert kr["algorithm"] == "RSA"
    assert kr["bits"] == 2048
    assert any("2048-bit" in i for i in kr["issues"])


def test_audit_ssh_keys_dsa_flagged(tmp_path: Path) -> None:
    """DSA keys are always flagged regardless of bit size."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()

    key = ssh_dir / "id_dsa"
    key.write_bytes(b"-----BEGIN DSA PRIVATE KEY-----\nfake\n")
    key.chmod(0o600)

    keygen_l_result = subprocess.CompletedProcess(
        args=[], returncode=0,
        stdout="1024 SHA256:dsafp1234567890abcdefghijklmnopqrstuvwxy user@host (DSA)",
        stderr="",
    )
    keygen_y_result = subprocess.CompletedProcess(
        args=[], returncode=255, stdout="",
        stderr="incorrect passphrase supplied to decrypt private key",
    )

    def mock_run(cmd, **kwargs):
        if cmd[1] == "-l":
            return keygen_l_result
        if cmd[1] == "-y":
            return keygen_y_result
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")

    with patch("guardian.sweeps.ssh_key_audit.subprocess.run", side_effect=mock_run):
        with patch("guardian.sweeps.ssh_key_audit.shutil.which", return_value="/usr/bin/ssh-keygen"):
            report, _ = audit_ssh_keys(ssh_dir=ssh_dir, check_github=False)

    kr = report["keys"][0]
    assert kr["algorithm"] == "DSA"
    assert any("deprecated" in i for i in kr["issues"])


def test_audit_ssh_keys_bad_permissions(tmp_path: Path) -> None:
    """Key with 644 permissions is flagged."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()

    key = ssh_dir / "id_ed25519"
    key.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n")
    key.chmod(0o644)

    keygen_l_result = subprocess.CompletedProcess(
        args=[], returncode=0,
        stdout="256 SHA256:fp12345678901234567890abcdefghijklmnopqr user@host (ED25519)",
        stderr="",
    )
    keygen_y_result = subprocess.CompletedProcess(
        args=[], returncode=255, stdout="",
        stderr="incorrect passphrase supplied to decrypt private key",
    )

    def mock_run(cmd, **kwargs):
        if cmd[1] == "-l":
            return keygen_l_result
        if cmd[1] == "-y":
            return keygen_y_result
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")

    with patch("guardian.sweeps.ssh_key_audit.subprocess.run", side_effect=mock_run):
        with patch("guardian.sweeps.ssh_key_audit.shutil.which", return_value="/usr/bin/ssh-keygen"):
            report, _ = audit_ssh_keys(ssh_dir=ssh_dir, check_github=False)

    kr = report["keys"][0]
    assert kr["permissions_ok"] is False
    assert any("permissions too open" in i for i in kr["issues"])


def test_audit_ssh_keys_github_cross_ref(tmp_path: Path) -> None:
    """GitHub cross-reference flags unregistered local keys and orphaned GitHub keys."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()

    key = ssh_dir / "id_ed25519"
    key.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n")
    key.chmod(0o600)

    local_fp = "SHA256:localkey1234567890abcdefghijklmnopqrstuv"
    keygen_l_result = subprocess.CompletedProcess(
        args=[], returncode=0,
        stdout=f"256 {local_fp} user@host (ED25519)",
        stderr="",
    )
    keygen_y_result = subprocess.CompletedProcess(
        args=[], returncode=255, stdout="",
        stderr="incorrect passphrase supplied to decrypt private key",
    )

    gh_output = "my-laptop\tauthentication\tSHA256:githubonlykey12345678901234567890ab\t2024-01-01"

    def mock_run(cmd, **kwargs):
        if cmd[0] == "ssh-keygen" and cmd[1] == "-l":
            return keygen_l_result
        if cmd[0] == "ssh-keygen" and cmd[1] == "-y":
            return keygen_y_result
        if cmd[0] == "gh":
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout=gh_output, stderr=""
            )
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")

    with patch("guardian.sweeps.ssh_key_audit.subprocess.run", side_effect=mock_run):
        with patch("guardian.sweeps.ssh_key_audit.shutil.which", return_value="/usr/bin/found"):
            report, _ = audit_ssh_keys(ssh_dir=ssh_dir, check_github=True)

    xref = report["github_cross_reference"]
    assert xref is not None
    assert xref["github_keys_count"] == 1
    # Local key not on GitHub
    assert len(xref["local_not_on_github"]) == 1
    assert xref["local_not_on_github"][0]["fingerprint"] == local_fp
    # GitHub key not local
    assert len(xref["github_not_local"]) == 1
    assert xref["github_not_local"][0]["title"] == "my-laptop"
    # Key entry should have registered_on_github=False
    kr = report["keys"][0]
    assert kr["registered_on_github"] is False
    assert any("not registered on GitHub" in i for i in kr["issues"])


def test_write_report(tmp_path: Path) -> None:
    from guardian.sweeps.ssh_key_audit import write_report

    report = {"test": True, "keys": []}
    out = tmp_path / "subdir" / "report.json"
    write_report(out, report)
    assert out.exists()
    import json
    loaded = json.loads(out.read_text())
    assert loaded["test"] is True
