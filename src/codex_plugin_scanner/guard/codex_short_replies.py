"""Ask Codex for short replies while CIGAR is on.

The native runtime owns the change (``publication_short_replies``): it writes
Codex's ``developer_instructions`` by default when CIGAR is turned on, never
touches instructions the user wrote, and remembers when the user turns it off.
This module only takes the Codex install lock and passes the request on.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .codex_lean_sessions import LeanSessionsError, _home_fields, _locked, config_path


def status(home_dir: Path, guard_home: Path, environ: Mapping[str, str] | None = None) -> dict[str, object]:
    return _ask("status", home_dir, guard_home, environ)


def enable(home_dir: Path, guard_home: Path, environ: Mapping[str, str] | None = None) -> dict[str, object]:
    with _locked(guard_home, config_path(home_dir, environ)):
        return _ask("enable", home_dir, guard_home, environ)


def disable(home_dir: Path, guard_home: Path, environ: Mapping[str, str] | None = None) -> dict[str, object]:
    with _locked(guard_home, config_path(home_dir, environ)):
        return _ask("disable", home_dir, guard_home, environ)


def ensure(home_dir: Path, guard_home: Path, environ: Mapping[str, str] | None = None) -> dict[str, object]:
    """The default when CIGAR turns on: on unless the user said no."""
    with _locked(guard_home, config_path(home_dir, environ)):
        return _ask("ensure", home_dir, guard_home, environ)


def _ask(action: str, home_dir: Path, guard_home: Path, environ: Mapping[str, str] | None) -> dict[str, object]:
    from .native_transition_files import publication

    answer = publication("short_replies", guard_home, action=action, **_home_fields(home_dir, environ))
    if not isinstance(answer, Mapping):
        raise ValueError("Codex short replies answer is malformed")
    error = answer.get("error")
    if isinstance(error, str):
        raise LeanSessionsError(error)
    return dict(answer)
