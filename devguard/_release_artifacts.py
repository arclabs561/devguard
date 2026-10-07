"""Reject known runtime email files in built distributions before upload."""

from __future__ import annotations

import argparse
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

RUNTIME_FILENAMES = frozenset(
    {
        ".guardian-email-history.json",
        ".guardian-email-thread",
        ".devguard-email-history.json",
        ".devguard-email-thread",
    }
)


def check_artifacts(directory: Path) -> list[str]:
    """Inspect member names only; never extract or print member contents."""
    errors: list[str] = []
    archives = sorted(directory.glob("*.tar.gz")) + sorted(directory.glob("*.whl"))
    if not archives:
        return ["No distribution archives found"]
    for archive in archives:
        try:
            if archive.name.endswith(".whl"):
                with zipfile.ZipFile(archive) as wheel:
                    members = wheel.namelist()
            else:
                with tarfile.open(archive, "r:gz") as sdist:
                    members = [member.name for member in sdist]
            forbidden = {
                PurePosixPath(member.replace("\\", "/")).name for member in members
            } & RUNTIME_FILENAMES
            if forbidden:
                errors.append(
                    f"{archive.name}: forbidden runtime files: {', '.join(sorted(forbidden))}"
                )
        except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile):
            errors.append(f"{archive.name}: unreadable distribution archive")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    errors = check_artifacts(args.directory)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print("Distribution archives contain no known runtime email filenames")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
