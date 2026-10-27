"""Test-side resident probes whose production callers are gone.

Each helper asks the resident one question directly so tests can pin its
answer. No production path calls them.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import _optional_string
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_directory_trust import _memo_lock, _remembered_asks
from codex_plugin_scanner.guard.native_request_context import (
    _DEFAULT_BUDGET_MS,
    NativeRequestContextFailure,
    _call,
)
from codex_plugin_scanner.guard.native_sensitive_request import _ask, _bool
from codex_plugin_scanner.guard.runtime.approval_context import approval_context_tokens_validation_reason
from codex_plugin_scanner.guard.runtime.shell_execution_context import (
    SHELL_CWD_NATIVE_UNAVAILABLE,
    SHELL_CWD_PATH_CHANGED,
    ShellExecutionContext,
    ShellExecutionSegment,
    _context_wire,
)


def native_shell_validate_segment(
    context: Mapping[str, Any],
    segment_index: int,
    *,
    guard_home: Path | None = None,
    budget_ms: int = _DEFAULT_BUDGET_MS,
) -> tuple[str | None, str | None] | NativeRequestContextFailure:
    """Re-read the filesystem for one modeled segment: ``(cwd, reason_code)``."""

    payload = _call(
        {"kind": "validate_segment", "body": {"context": dict(context), "segment_index": segment_index}},
        source="hook",
        guard_home=guard_home,
        budget_ms=budget_ms,
    )
    if isinstance(payload, NativeRequestContextFailure):
        return payload
    cwd, reason = payload.get("effective_cwd"), payload.get("reason_code")
    if (
        set(payload) != {"effective_cwd", "reason_code", "context_hash", "segment_hash"}
        or not (cwd is None or isinstance(cwd, str))
        or not (reason is None or isinstance(reason, str))
        or (cwd is None) == (reason is None)
    ):
        return NativeRequestContextFailure("native_request_context_payload_invalid")
    return cwd, reason


def validate_shell_execution_segment(
    context: ShellExecutionContext,
    segment: ShellExecutionSegment,
) -> tuple[Path | None, str | None]:
    """Revalidate a modeled cwd immediately before a filesystem-sensitive use."""

    if not segment.complete or segment.effective_cwd is None or segment.cwd_identity is None:
        return None, segment.reason_code or context.reason_code or SHELL_CWD_PATH_CHANGED
    if context.workspace_root is None or context.workspace_identity is None:
        return None, context.reason_code or SHELL_CWD_PATH_CHANGED
    wire = _single_segment_wire(context, segment)
    result = native_shell_validate_segment(wire, 0)
    if isinstance(result, NativeRequestContextFailure):
        return None, SHELL_CWD_NATIVE_UNAVAILABLE
    cwd, reason = result
    return (Path(cwd) if cwd is not None else None), reason


def _single_segment_wire(context: ShellExecutionContext, segment: ShellExecutionSegment) -> dict[str, Any]:
    """Segment checks and hashes depend only on the workspace and the segment."""

    return _context_wire(context, (segment,))


def _runtime_saved_allow_validation_reason(
    decision: Mapping[str, object],
    *,
    artifact: GuardArtifact,
    artifact_hash: str,
) -> str | None:
    """Require saved runtime allows to carry the complete current v1 context."""

    if _optional_string(decision.get("action")) != "allow":
        return None
    stored_hash = _optional_string(decision.get("artifact_hash"))
    return approval_context_tokens_validation_reason(stored_hash, artifact_hash)


def native_benign_file_read(tool_name: object, arguments: object, *, cwd: Path | None, home_dir: Path | None) -> bool:
    return _bool(_ask("benign_file_read", {"tool_name": tool_name, "arguments": arguments}, cwd=cwd, home_dir=home_dir))


def _read_only_lookup_target_is_safe(target: str, *, allow_dirs: bool, home_dir: Path | None = None) -> bool:
    return native_read_only_lookup_target_is_safe(target, allow_dirs=allow_dirs, home_dir=home_dir)


def native_read_only_lookup_target_is_safe(target: str, *, allow_dirs: bool, home_dir: Path | None) -> bool:
    return _bool(
        _ask(
            "read_only_lookup_target_is_safe",
            {"target": target, "allow_dirs": allow_dirs},
            cwd=None,
            home_dir=home_dir,
        )
    )


def clear_remembered_directory_trust() -> None:
    """Forget the directory-trust answers this process has already settled.

    Only tests need this: a run keeps the memo for its whole life, so nothing
    in production ever clears it.
    """

    with _memo_lock:
        _remembered_asks.clear()
