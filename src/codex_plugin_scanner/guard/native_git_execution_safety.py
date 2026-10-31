"""Resident bridge for the ``git_execution_safety`` op (RTM-032).

``runtime.git_execution_safety`` forwards observed facts (cwd, home, account
home, groups, a bounded environment snapshot, and the arguments under review)
to the resident. Rust owns every verdict. This module never evaluates Git
configuration, binaries, or hooks; any transport failure, malformed result, or
missing capability returns ``None`` and callers fail closed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .native_resident_decision import BoundCall, ResidentCallError, bound_resident_call

_REQUEST_SCHEMA = "guard-git-execution-safety-request.v1"
_RESULT_SCHEMA = "guard-git-execution-safety-result.v1"
_SNAPSHOT_NAMES = frozenset(
    {
        "SSH_ASKPASS",
        "PATH",
        "HOME",
        "XDG_CONFIG_HOME",
        "PAGER",
        "USERPROFILE",
        "SYSTEMROOT",
        "WINDIR",
    }
)
_DEFAULT_TIMEOUT_SECONDS = 8.0
_CALL = BoundCall(
    operation="git_execution_safety",
    feature="git-execution-safety-v1",
    prefix="native_git_execution_safety",
    result_schema=_RESULT_SCHEMA,
    max_request_bytes=128 * 1024,
    timeout_seconds=_DEFAULT_TIMEOUT_SECONDS,
    check_circuit=True,
    transport_failure="unavailable",
)

_request_counter = 0


@dataclass(frozen=True)
class GitSafetyAnswer:
    """The resident's verdict for one check."""

    allowed: bool
    resolved_path: str | None


def _environment_snapshot() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key.startswith("GIT_") or key in _SNAPSHOT_NAMES}


# The source-search and locale names a resident command review also reads.
_TOOL_SNAPSHOT_NAMES = frozenset({"RIPGREP_CONFIG_PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMP", "TEMP", "TMPDIR"})


def _tool_environment_snapshot() -> dict[str, str]:
    """The git snapshot plus the names a resident command review reads."""
    snapshot = _environment_snapshot()
    snapshot.update({key: value for key, value in os.environ.items() if key in _TOOL_SNAPSHOT_NAMES})
    return snapshot


def _account_home_directory() -> str | None:
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, KeyError, OSError, RuntimeError, AttributeError):
        return None


def _process_groups() -> list[int]:
    getgroups = getattr(os, "getgroups", None)
    if getgroups is None:
        return []
    try:
        return sorted({int(group) for group in getgroups()})
    except OSError:
        return []


def git_execution_safety_native(
    check: str,
    *,
    cwd: Path | None = None,
    git_binary: Path | None = None,
    git_path: Path | None = None,
    arguments: list[str] | None = None,
    branch: str | None = None,
    reference: str | None = None,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> GitSafetyAnswer | None:
    """Ask the resident for a git-execution-safety verdict.

    Returns ``None`` when no authoritative answer is available.
    """

    global _request_counter
    try:
        home = str(Path.home())
        # The resident resolves relative paths against its own directory, so
        # the caller cwd must be made absolute here (the retired Python
        # implementation did) before it is sent.
        request_cwd = os.path.abspath(cwd) if cwd is not None else home
    except (OSError, RuntimeError):
        return None
    _request_counter += 1
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"ges-{os.getpid()}-{_request_counter}",
        "check": check,
        "cwd": request_cwd,
        "home": home,
        "groups": _process_groups(),
        "environment": _environment_snapshot(),
        "arguments": list(arguments or []),
    }
    account_home = _account_home_directory()
    if account_home is not None:
        request["account_home"] = account_home
    for name, value in (
        ("git_binary", git_binary),
        ("git_path", git_path),
        ("branch", branch),
        ("reference", reference),
    ):
        if value is not None:
            request[name] = str(value)
    try:
        reply = bound_resident_call(_CALL, request, timeout_seconds=timeout_seconds)
    except ResidentCallError:
        return None
    envelope = reply.envelope
    if not isinstance(envelope.get("allowed"), bool):
        reply.fail()
        return None
    reply.healthy()
    if envelope.get("status") != "ok" or envelope.get("code") != "ok":
        return GitSafetyAnswer(False, None)
    resolved = envelope.get("resolved_path")
    return GitSafetyAnswer(bool(envelope["allowed"]), resolved if isinstance(resolved, str) else None)
