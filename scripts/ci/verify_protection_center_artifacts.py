#!/usr/bin/env python3
"""Fail closed if Protection Center proof artifacts contain known secret material."""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path

_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
_GENERIC_NEEDLES = (
    b"guard-token",
    b"approval_password",
    b"approval_totp_code",
    b"session_nonce",
    b"BEGIN " + b"PRIVATE KEY",
    b"BEGIN OPENSSH " + b"PRIVATE KEY",
)


def _iter_files(path: Path) -> Iterator[Path]:
    if path.is_file():
        yield path
        return
    if not path.is_dir():
        raise SystemExit(f"Protection Center artifact path does not exist: {path}")
    for candidate in sorted(path.rglob("*")):
        if candidate.is_symlink():
            raise SystemExit(f"Protection Center proof contains a symlink: {candidate}")
        if candidate.is_file():
            yield candidate


def _scan_file(path: Path, secret: bytes | None) -> None:
    size = path.stat().st_size
    if size > _MAX_ARTIFACT_BYTES:
        raise SystemExit(
            f"Protection Center proof artifact is unexpectedly large: {path} ({size} bytes)"
        )
    payload = path.read_bytes()
    needles = list(_GENERIC_NEEDLES)
    if secret:
        needles.append(secret)
    for needle in needles:
        if needle and needle in payload:
            raise SystemExit(f"Sensitive marker found in Protection Center proof artifact: {path}")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        raise SystemExit("usage: verify_protection_center_artifacts.py PATH [PATH ...]")
    raw_secret = os.environ.get("HOL_GUARD_ARTIFACT_SECRET", "")
    secret = raw_secret.encode("utf-8") if len(raw_secret) >= 16 else None
    checked = 0
    for raw_path in argv[1:]:
        for path in _iter_files(Path(raw_path)):
            _scan_file(path, secret)
            checked += 1
    if checked == 0:
        raise SystemExit("No Protection Center proof artifacts were found")
    print(f"Protection Center artifact secrecy check passed for {checked} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
