"""Audit the exact Cargo.lock shipped in a public crates.io release."""

import gzip
import hashlib
import io
import json
import re
import tarfile
import tempfile
from dataclasses import asdict
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from devguard.sweeps.dependency_audit import _audit_repo


def _read_url(url: str, limit: int) -> bytes:
    request = Request(url, headers={"User-Agent": "devguard (github.com/arclabs561/devguard)"})
    with urlopen(request, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("registry input exceeds size limit")
    return data


def _release_lock(data: bytes, prefix: str, checksum: str) -> bytes:
    if hashlib.sha256(data).hexdigest() != checksum:
        raise ValueError("registry archive checksum mismatch")
    max_tar_bytes = 128 * 1024 * 1024
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        raw = compressed.read(max_tar_bytes + 1)
    if len(raw) > max_tar_bytes:
        raise ValueError("release archive exceeds size limit")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        locks = [m for m in archive if m.name == f"{prefix}/Cargo.lock"]
        if len(locks) != 1 or not locks[0].isfile() or locks[0].size > 8 * 1024 * 1024:
            raise ValueError("release must contain one regular Cargo.lock within the size limit")
        stream = archive.extractfile(locks[0])
        if stream is None:
            raise ValueError("could not read release Cargo.lock")
        return stream.read()


def audit_crate_release(name: str, version: str) -> dict:
    if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_-]{0,63}", name) or not re.fullmatch(
        r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version
    ):
        raise ValueError("expected a crates.io package name and exact version")
    key = name.lower()
    if len(key) <= 2:
        prefix = str(len(key))
    elif len(key) == 3:
        prefix = "3/" + key[0]
    else:
        prefix = key[:2] + "/" + key[2:4]
    source = {"registry": "crates.io", "name": name, "version": version}
    try:
        lines = _read_url(f"https://index.crates.io/{prefix}/{key}", 16 * 1024 * 1024)
        entries = (json.loads(line) for line in lines.splitlines())
        entry = next((row for row in entries if row["vers"] == version), None)
        if entry is None or entry["name"].lower() != key:
            raise ValueError("version absent from registry index")
        published = entry["name"]
        filename = f"{published}-{version}"
        source["sha256"] = entry["cksum"]
        data = _read_url(
            f"https://static.crates.io/crates/{published}/{filename}.crate", 32 * 1024 * 1024
        )
        lock = _release_lock(data, filename, source["sha256"])
        source["lock_sha256"] = hashlib.sha256(lock).hexdigest()
        with tempfile.TemporaryDirectory(prefix="devguard-crate-") as directory:
            path = Path(directory)
            (path / "Cargo.lock").write_bytes(lock)
            result = _audit_repo(path, ["osv-scanner"], 120, explicit=True, release_lock=True)
        row = asdict(result)
        row["repo_path"] = f"{filename}/Cargo.lock"
        return {
            "source": source,
            "status": "incomplete" if result.error else "complete",
            "audit": row,
        }
    except (OSError, URLError, EOFError, KeyError, tarfile.TarError, ValueError) as exc:
        return {"source": source, "status": "incomplete", "error": str(exc)}
