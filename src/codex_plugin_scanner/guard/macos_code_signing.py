"""Shared macOS publisher-signature verification, answered by the native runtime."""

from __future__ import annotations

import sys
from pathlib import Path

_FEATURE = "native-macos-code-signing-v1"
_COMMAND = "macos-code-signing"
_SCHEMA = "macos-code-signing.v1"
_OUTPUT_LIMIT = 64 * 1024
_SEAL_TIMEOUT_SECONDS = 40.0
_TREE_TIMEOUT_SECONDS = 1800.0


def _answer(request: dict[str, object], timeout_seconds: float) -> dict[str, object] | None:
    from .mdm.runtime_request import runtime_answer

    return runtime_answer(
        _FEATURE,
        _COMMAND,
        {"schema": _SCHEMA, **request},
        output_limit=_OUTPUT_LIMIT,
        timeout_seconds=timeout_seconds,
    )


def verified_macos_signing_team(executable: Path, *, deep: bool = False, timeout: float = 5.0) -> str | None:
    """The verified Team ID, or `None` when it cannot be verified."""

    if sys.platform != "darwin":
        return None
    timeout_ms = min(max(int(timeout * 1000), 1), 120_000)
    request: dict[str, object] = {"op": "team", "path": str(executable), "deep": deep, "timeout_ms": timeout_ms}
    answer = _answer(request, 2 * timeout_ms / 1000 + 5.0)
    team = answer.get("team") if answer is not None else None
    return team if isinstance(team, str) and team else None


def macos_bundle_sealed(launcher: Path) -> bool:
    """Whether a onedir launcher is signed as an app bundle with sealed resources."""

    answer = _answer({"op": "sealed", "path": str(launcher)}, _SEAL_TIMEOUT_SECONDS)
    return answer is not None and answer.get("sealed") is True


def macos_tree_signature_failure(tree: Path, *, expected_team: str) -> str | None:
    """The reason code for the first Mach-O file without `expected_team`, or `None`."""

    request: dict[str, object] = {"op": "tree", "path": str(tree), "expected_team": expected_team}
    answer = _answer(request, _TREE_TIMEOUT_SECONDS)
    if answer is None or "failure" not in answer:
        return "desktop_core_signature_invalid"
    failure = answer["failure"]
    if failure is None:
        return None
    return failure if isinstance(failure, str) else "desktop_core_signature_invalid"


__all__ = ["macos_bundle_sealed", "macos_tree_signature_failure", "verified_macos_signing_team"]
