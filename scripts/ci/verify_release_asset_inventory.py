#!/usr/bin/env python3
"""Verify retry-safe GitHub release assets owned by Guard workflows."""

from __future__ import annotations

import hashlib
import re
import stat
import sys
from pathlib import Path

SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
CORE_TARGET = "aarch64-apple-darwin"


def _regular_file_names(directory: Path) -> set[str]:
    return {entry.name for entry in directory.iterdir() if stat.S_ISREG(entry.lstat().st_mode)}


def verify_release_assets(release_dir: Path, dist_dir: Path, version: str, channel: str) -> None:
    """Reject unowned assets and verify optional co-owned asset sets."""
    if channel not in {"alpha", "stable"}:
        raise ValueError(f"Unsupported release channel: {channel}")
    owned_names = _regular_file_names(dist_dir)
    mcpb_name = f"hol-guard-{version}.mcpb"
    checksum_name = f"{mcpb_name}.sha256"
    mcpb_names = {mcpb_name, checksum_name}
    core_base = f"hol-guard-core-{version}-{CORE_TARGET}"
    core_names = {core_base, f"{core_base}.json", f"{core_base}.attested.json"}
    co_owned_names = mcpb_names | (core_names if channel == "alpha" else set())
    allowed_names = owned_names | co_owned_names
    release_names = _regular_file_names(release_dir)
    unexpected_names = sorted(release_names - allowed_names)
    if unexpected_names:
        names = ", ".join(unexpected_names)
        raise ValueError(f"Unexpected release asset: {names}")

    present_mcpb_names = release_names & mcpb_names
    if present_mcpb_names and present_mcpb_names != mcpb_names:
        raise ValueError("MCPB release asset and checksum must both be present")
    present_core_names = release_names & core_names
    if present_core_names and present_core_names != core_names:
        raise ValueError("Desktop Core release assets must be a complete set")
    if not present_mcpb_names:
        return

    checksum_lines = (release_dir / checksum_name).read_text(encoding="utf-8").splitlines()
    if len(checksum_lines) != 1:
        raise ValueError("MCPB checksum must contain exactly one line")
    checksum_fields = checksum_lines[0].split()
    if not checksum_fields or SHA256_PATTERN.fullmatch(checksum_fields[0]) is None:
        raise ValueError("MCPB checksum does not contain a valid SHA-256 digest")
    actual_digest = hashlib.sha256((release_dir / mcpb_name).read_bytes()).hexdigest()
    if actual_digest != checksum_fields[0]:
        raise ValueError("MCPB release asset does not match its checksum")


def main() -> int:
    if len(sys.argv) != 5:
        print(f"Usage: {Path(sys.argv[0]).name} RELEASE_DIR DIST_DIR VERSION CHANNEL", file=sys.stderr)
        return 2
    try:
        verify_release_assets(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4])
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
