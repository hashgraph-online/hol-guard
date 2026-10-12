"""Parity entry points for native credential-path expressions.

Contained profiles are built in the resident. The parity recorder calls these
functions so the recorded native replies stay attached to this module. They
are not a second source for the macOS profile.
"""

from __future__ import annotations

from pathlib import Path

from ..native_restricted_pytest import restricted_native


def _read_only_credential_patterns() -> tuple[str, ...]:
    return tuple(restricted_native("credential_patterns", {}, list))


def _seatbelt_string(path: Path | str) -> str:
    return restricted_native("seatbelt_string", {"value": str(path)}, str)


def _read_only_credential_denials(*, hide_metadata: bool = False) -> tuple[str, ...]:
    return tuple(restricted_native("credential_denials", {"hide_metadata": hide_metadata}, list))
