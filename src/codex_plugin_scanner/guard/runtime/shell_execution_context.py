"""Shell working-directory execution context: native adapter.

The resident owns path resolution, symlink and descriptor identity checks, the
directory-change model, and every context hash. This module only keeps the
public dataclass shapes and converts the resident's wire reply into them. A
context is a claim: validation and hashing go back to the resident, and an
unavailable resident yields an incomplete context (never an allow).
"""

from __future__ import annotations

import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..native_context import _UNBOUND_PREFIX
from ..native_request_context import (
    NativeRequestContextFailure,
    RequestContextSource,
    native_request_context_build,
    native_shell_hashes,
    native_shell_validate_segment,
)
from ._shell_execution_context_support import (
    SHELL_CWD_AMBIGUOUS_STACK,
    SHELL_CWD_MISSING_DIRECTORY,
    SHELL_CWD_NOT_DIRECTORY,
    SHELL_CWD_PATH_CHANGED,
    SHELL_CWD_STACK_LIMIT,
    SHELL_CWD_SYMLINK_ESCAPE,
    SHELL_CWD_UNREADABLE_DIRECTORY,
    SHELL_CWD_UNRESOLVED_CONTROL_FLOW,
    SHELL_CWD_UNRESOLVED_EXPRESSION,
    SHELL_CWD_UNRESOLVED_PARENT_SHELL,
    SHELL_CWD_UNRESOLVED_SYNTAX,
    SHELL_CWD_WORKSPACE_ESCAPE,
    SHELL_DIRECTORY_COMMAND,
    ShellPathIdentity,
    ShellPathProof,
    last_flow_operator,
    shell_path_identity_payload,
)

SHELL_CWD_NATIVE_UNAVAILABLE = "shell_cwd_native_unavailable"


@dataclass(frozen=True, slots=True)
class ShellExecutionSegment:
    """The proven execution directory for one ordered shell segment."""

    tokens: tuple[str, ...]
    segment_index: int
    control_before: tuple[str, ...]
    control_after: tuple[str, ...]
    effective_cwd: Path | None
    cwd_identity: ShellPathIdentity | None
    cwd_path_proofs: tuple[ShellPathProof, ...]
    cwd_source: str
    directory_stack: tuple[Path, ...]
    complete: bool
    reason_code: str | None = None
    directory_operation: str | None = None

    @property
    def command_text(self) -> str:
        return shlex.join(self.tokens)

    @property
    def control_operator(self) -> str | None:
        return last_flow_operator(self.control_after)


@dataclass(frozen=True, slots=True)
class _NativeBinding:
    """Resident-issued hashes, valid only for the exact wire form they cover."""

    wire: Mapping[str, Any]
    context_hash: str
    segment_hashes: tuple[str, ...]
    metadata: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ShellExecutionContext:
    """Canonical, immutable directory context for an entire shell command."""

    command_text: str
    initial_cwd: Path | None
    workspace_root: Path | None
    workspace_identity: ShellPathIdentity | None
    segments: tuple[ShellExecutionSegment, ...]
    complete: bool
    reason_code: str | None
    directory_change_present: bool
    native: _NativeBinding | None = field(default=None, compare=False, repr=False)

    @property
    def effective_cwds(self) -> tuple[Path, ...]:
        result: list[Path] = []
        for segment in self.segments:
            if segment.directory_operation is not None or not segment.complete or segment.effective_cwd is None:
                continue
            if segment.effective_cwd not in result:
                result.append(segment.effective_cwd)
        return tuple(result)

    @property
    def context_hash(self) -> str:
        return shell_execution_context_hash(self)


def _flag(value: object) -> bool:
    if not isinstance(value, bool):
        raise ValueError("shell context flag must be a boolean")
    return value


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("shell context field must be a list of strings")
    return tuple(value)


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("shell context field must be a string")
    return value


def _index(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("shell context index must be an integer")
    return value


def _optional_str(value: object) -> str | None:
    if value is not None and not isinstance(value, str):
        raise ValueError("shell context field must be a string")
    return value


def _identity_from_wire(value: Mapping[str, Any] | None) -> ShellPathIdentity | None:
    if value is None:
        return None
    return ShellPathIdentity(
        device=value["device"],
        inode=value["inode"],
        mode=value["mode"],
        change_time_ns=value["change_time_ns"],
        creation_time_ns=value["creation_time_ns"],
    )


def _required_identity(value: Mapping[str, Any]) -> ShellPathIdentity:
    identity = _identity_from_wire(value)
    if identity is None:
        raise ValueError("shell path proof identity is required")
    return identity


def _optional_text(path: Path | None) -> str | None:
    return str(path) if path is not None else None


def _segment_wire(segment: ShellExecutionSegment) -> dict[str, Any]:
    return {
        "tokens": list(segment.tokens),
        "segment_index": segment.segment_index,
        "control_before": list(segment.control_before),
        "control_after": list(segment.control_after),
        "effective_cwd": _optional_text(segment.effective_cwd),
        "cwd_identity": shell_path_identity_payload(segment.cwd_identity),
        "cwd_path_proofs": [
            {
                "lexical_path": str(proof.lexical_path),
                "resolved_path": str(proof.resolved_path),
                "identity": shell_path_identity_payload(proof.identity),
            }
            for proof in segment.cwd_path_proofs
        ],
        "cwd_source": segment.cwd_source,
        "directory_stack": [str(path) for path in segment.directory_stack],
        "complete": segment.complete,
        "reason_code": segment.reason_code,
        "directory_operation": segment.directory_operation,
    }


def _context_wire(
    context: ShellExecutionContext,
    segments: Sequence[ShellExecutionSegment] | None = None,
) -> dict[str, Any]:
    return {
        "command_text": context.command_text,
        "initial_cwd": _optional_text(context.initial_cwd),
        "workspace_root": _optional_text(context.workspace_root),
        "workspace_identity": shell_path_identity_payload(context.workspace_identity),
        "segments": [_segment_wire(segment) for segment in (context.segments if segments is None else segments)],
        "complete": context.complete,
        "reason_code": context.reason_code,
        "directory_change_present": context.directory_change_present,
    }


def _segment_from_wire(value: Mapping[str, Any]) -> ShellExecutionSegment:
    return ShellExecutionSegment(
        tokens=_strings(value["tokens"]),
        segment_index=_index(value["segment_index"]),
        control_before=_strings(value["control_before"]),
        control_after=_strings(value["control_after"]),
        effective_cwd=Path(value["effective_cwd"]) if value["effective_cwd"] is not None else None,
        cwd_identity=_identity_from_wire(value["cwd_identity"]),
        cwd_path_proofs=tuple(
            ShellPathProof(
                lexical_path=Path(proof["lexical_path"]),
                resolved_path=Path(proof["resolved_path"]),
                identity=_required_identity(proof["identity"]),
            )
            for proof in value["cwd_path_proofs"]
        ),
        cwd_source=_text(value["cwd_source"]),
        directory_stack=tuple(Path(item) for item in _strings(value["directory_stack"])),
        complete=_flag(value["complete"]),
        reason_code=_optional_str(value["reason_code"]),
        directory_operation=_optional_str(value["directory_operation"]),
    )


def _context_from_report(report: Mapping[str, Any]) -> ShellExecutionContext:
    wire = report["context"]
    return ShellExecutionContext(
        command_text=_text(wire["command_text"]),
        initial_cwd=Path(wire["initial_cwd"]) if wire["initial_cwd"] is not None else None,
        workspace_root=Path(wire["workspace_root"]) if wire["workspace_root"] is not None else None,
        workspace_identity=_identity_from_wire(wire["workspace_identity"]),
        segments=tuple(_segment_from_wire(segment) for segment in wire["segments"]),
        complete=_flag(wire["complete"]),
        reason_code=_optional_str(wire["reason_code"]),
        directory_change_present=_flag(wire["directory_change_present"]),
        native=_NativeBinding(
            wire=wire,
            context_hash=report["context_hash"],
            segment_hashes=tuple(report["segment_hashes"]),
            metadata=report["metadata"],
        ),
    )


def _unavailable_context(command_text: str, code: str) -> ShellExecutionContext:
    return ShellExecutionContext(
        command_text=command_text,
        initial_cwd=None,
        workspace_root=None,
        workspace_identity=None,
        segments=(),
        complete=False,
        reason_code=code or SHELL_CWD_NATIVE_UNAVAILABLE,
        directory_change_present=True,
    )


def model_shell_execution_context(
    command_text: str,
    *,
    cwd: Path | None = None,
    workspace_root: Path | None = None,
    home_dir: Path | None = None,
    source: RequestContextSource = "hook",
) -> ShellExecutionContext:
    """Ask the resident to model literal shell directory changes."""

    result = native_request_context_build(
        source=source,
        script=command_text,
        cwd=cwd,
        workspace=workspace_root,
        home_dir=home_dir,
    )
    if isinstance(result, NativeRequestContextFailure) or result.shell is None:
        return _unavailable_context(command_text, SHELL_CWD_NATIVE_UNAVAILABLE)
    try:
        return _context_from_report(result.shell)
    except (KeyError, TypeError, ValueError, AttributeError):
        # A reply that decodes badly is not a context: stay incomplete.
        return _unavailable_context(command_text, SHELL_CWD_NATIVE_UNAVAILABLE)


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


def _unbound_hash(label: str) -> str:
    return f"{_UNBOUND_PREFIX}{label}"


def shell_execution_segment_hash(
    context: ShellExecutionContext,
    segment: ShellExecutionSegment,
) -> str:
    """Return an approval-safe identity for one segment and its full command."""

    wire = _single_segment_wire(context, segment)
    binding = context.native
    index = segment.segment_index
    if binding is not None and 0 <= index < len(binding.segment_hashes):
        issued = dict(binding.wire)
        shared = ("command_text", "workspace_root", "workspace_identity")
        if all(issued[key] == wire[key] for key in shared) and issued["segments"][index] == wire["segments"][0]:
            return binding.segment_hashes[index]
    result = native_shell_hashes(wire, 0)
    if isinstance(result, NativeRequestContextFailure) or result[1] is None:
        return _unbound_hash("shell-segment")
    return result[1]


def shell_execution_context_hash(context: ShellExecutionContext) -> str:
    binding = context.native
    wire = _context_wire(context)
    if binding is not None and dict(binding.wire) == wire:
        return binding.context_hash
    result = native_shell_hashes(wire)
    if isinstance(result, NativeRequestContextFailure):
        return _unbound_hash("shell-context")
    return result[0]


def shell_execution_context_metadata(context: ShellExecutionContext) -> dict[str, object]:
    """Return bounded metadata suitable for runtime artifacts and approval identity."""

    binding = context.native
    wire = _context_wire(context)
    if binding is not None and dict(binding.wire) == wire:
        return dict(binding.metadata)
    result = native_shell_hashes(wire)
    if isinstance(result, NativeRequestContextFailure):
        effective = [str(path) for path in context.effective_cwds]
        return {
            "shell_execution_context_hash": _unbound_hash("shell-context"),
            "shell_execution_context_complete": False,
            "shell_execution_context_reason_code": SHELL_CWD_NATIVE_UNAVAILABLE,
            "shell_execution_effective_cwds": effective,
            "effective_cwd": effective[-1] if effective else None,
        }
    return dict(result[2])


__all__ = [
    "SHELL_CWD_AMBIGUOUS_STACK",
    "SHELL_CWD_MISSING_DIRECTORY",
    "SHELL_CWD_NATIVE_UNAVAILABLE",
    "SHELL_CWD_NOT_DIRECTORY",
    "SHELL_CWD_PATH_CHANGED",
    "SHELL_CWD_STACK_LIMIT",
    "SHELL_CWD_SYMLINK_ESCAPE",
    "SHELL_CWD_UNREADABLE_DIRECTORY",
    "SHELL_CWD_UNRESOLVED_CONTROL_FLOW",
    "SHELL_CWD_UNRESOLVED_EXPRESSION",
    "SHELL_CWD_UNRESOLVED_PARENT_SHELL",
    "SHELL_CWD_UNRESOLVED_SYNTAX",
    "SHELL_CWD_WORKSPACE_ESCAPE",
    "SHELL_DIRECTORY_COMMAND",
    "ShellExecutionContext",
    "ShellExecutionSegment",
    "model_shell_execution_context",
    "shell_execution_context_hash",
    "shell_execution_context_metadata",
    "shell_execution_segment_hash",
    "validate_shell_execution_segment",
]
