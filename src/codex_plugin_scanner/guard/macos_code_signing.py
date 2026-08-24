"""Shared macOS publisher-signature verification."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def verified_macos_signing_team(executable: Path, *, deep: bool = False, timeout: float = 5.0) -> str | None:
    if sys.platform != "darwin":
        return None
    verify_command = ["/usr/bin/codesign", "--verify"]
    if deep:
        verify_command.append("--deep")
    verify_command.extend(("--strict", str(executable)))
    try:
        verified = subprocess.run(
            verify_command,
            check=False,
            capture_output=True,
            timeout=timeout,
        )
        details = subprocess.run(
            ["/usr/bin/codesign", "--display", "--verbose=4", str(executable)],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if verified.returncode != 0 or details.returncode != 0:
        return None
    for line in details.stderr.splitlines():
        if not line.startswith("TeamIdentifier="):
            continue
        team = line.partition("=")[2].strip()
        return team if team and team != "not set" else None
    return None


__all__ = ["verified_macos_signing_team"]
