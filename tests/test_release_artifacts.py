"""Regression tests for the distribution upload boundary."""

import io
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from devguard._release_artifacts import check_artifacts


def write_archive(directory: Path, kind: str, member: str) -> Path:
    archive = directory / f"package.{kind}"
    payload = b"SYNTHETIC_CONTENT_MUST_NOT_APPEAR"
    if kind == "whl":
        with zipfile.ZipFile(archive, "w") as wheel:
            wheel.writestr(member, payload)
    else:
        with tarfile.open(archive, "w:gz") as sdist:
            info = tarfile.TarInfo(member)
            info.size = len(payload)
            sdist.addfile(info, io.BytesIO(payload))
    return archive


@pytest.mark.parametrize("kind", ["whl", "tar.gz"])
@pytest.mark.parametrize("prefix", ["", "package/nested/"])
@pytest.mark.parametrize(
    "filename",
    [
        ".guardian-email-history.json",
        ".guardian-email-thread",
        ".devguard-email-history.json",
        ".devguard-email-thread",
    ],
)
def test_known_runtime_files_block_upload(tmp_path, kind, prefix, filename):
    write_archive(tmp_path, kind, prefix + filename)
    errors = check_artifacts(tmp_path)
    assert len(errors) == 1
    assert filename in errors[0]
    assert "SYNTHETIC_CONTENT_MUST_NOT_APPEAR" not in errors[0]


@pytest.mark.parametrize("kind", ["whl", "tar.gz"])
def test_benign_members_are_allowed(tmp_path, kind):
    write_archive(tmp_path, kind, "package/tests/email_history_fixture.json")
    assert check_artifacts(tmp_path) == []


@pytest.mark.parametrize("kind", ["whl", "tar.gz"])
def test_unreadable_archive_is_an_error(tmp_path, kind):
    (tmp_path / f"package.{kind}").write_bytes(b"not an archive")
    assert check_artifacts(tmp_path) == [f"package.{kind}: unreadable distribution archive"]


def test_missing_archives_are_an_error(tmp_path):
    assert check_artifacts(tmp_path) == ["No distribution archives found"]
    assert check_artifacts(tmp_path / "missing") == ["No distribution archives found"]


def test_command_exit_prevents_upload_and_redacts_contents(tmp_path):
    write_archive(tmp_path, "tar.gz", "package/.guardian-email-history.json")
    proc = subprocess.run(
        [sys.executable, "-m", "devguard._release_artifacts", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 1
    assert ".guardian-email-history.json" in proc.stderr
    assert "SYNTHETIC_CONTENT_MUST_NOT_APPEAR" not in proc.stdout + proc.stderr


def test_package_build_excludes_runtime_files_without_git(tmp_path):
    """Use the real build configuration, including the wheel-from-sdist boundary."""
    source = Path(__file__).resolve().parents[1]
    for filename in ("pyproject.toml", "README.md"):
        shutil.copyfile(source / filename, tmp_path / filename)
    package = tmp_path / "devguard"
    package.mkdir()
    shutil.copyfile(source / "devguard/__init__.py", package / "__init__.py")
    for directory in (tmp_path, package):
        for filename in (
            ".guardian-email-history.json",
            ".guardian-email-thread",
            ".devguard-email-history.json",
            ".devguard-email-thread",
        ):
            (directory / filename).write_text("SYNTHETIC_RUNTIME_DATA")
    proc = subprocess.run(["uv", "build"], cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    archives = tmp_path / "dist"
    assert len(list(archives.glob("*.tar.gz"))) == 1
    assert len(list(archives.glob("*.whl"))) == 1
    assert check_artifacts(archives) == []
