"""Test-side shell execution context and request-context build probes.

Production reads the shell working-directory model inside the resident. These
helpers keep the old Python adapter shapes so tests can pin the resident's
build, hash and decode contract directly. No production path calls them.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard import native_request_context as _client
from codex_plugin_scanner.guard.native_context import _UNBOUND_PREFIX
from codex_plugin_scanner.guard.native_request_context import (
    _DEFAULT_BUDGET_MS,
    NativeRequestContextFailure,
    RequestContextSource,
    _absolute_text,
)

_CONTEXT_SCHEMA = "guard-request-context.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")

SHELL_CWD_UNRESOLVED_EXPRESSION = "shell_cwd_unresolved_expression"
SHELL_CWD_MISSING_DIRECTORY = "shell_cwd_missing_directory"
SHELL_CWD_NOT_DIRECTORY = "shell_cwd_not_directory"
SHELL_CWD_UNREADABLE_DIRECTORY = "shell_cwd_unreadable_directory"
SHELL_CWD_AMBIGUOUS_STACK = "shell_cwd_ambiguous_stack"
SHELL_CWD_STACK_LIMIT = "shell_cwd_stack_limit"
SHELL_CWD_WORKSPACE_ESCAPE = "shell_cwd_workspace_escape"
SHELL_CWD_SYMLINK_ESCAPE = "shell_cwd_symlink_escape"
SHELL_CWD_UNRESOLVED_CONTROL_FLOW = "shell_cwd_unresolved_control_flow"
SHELL_CWD_UNRESOLVED_PARENT_SHELL = "shell_cwd_unresolved_parent_shell_effect"
SHELL_CWD_UNRESOLVED_SYNTAX = "shell_cwd_unresolved_syntax"
SHELL_CWD_PATH_CHANGED = "shell_cwd_path_changed"

SHELL_DIRECTORY_COMMAND = re.compile(
    r"(?:^|(?:&&|\|\||[;|&(){}\n]))\s*"
    r"(?:(?:builtin|command|time)\s+(?:-[^\s]+\s+)*|function\s+|!\s+)?"
    r"(?:cd|pushd|popd)\b"
)


@dataclass(frozen=True, slots=True)
class ShellPathIdentity:
    """Filesystem identity captured without retaining an open descriptor."""

    device: int
    inode: int
    mode: int
    change_time_ns: int
    creation_time_ns: int


def shell_path_identity_payload(identity: ShellPathIdentity | None) -> dict[str, int] | None:
    """Return the stable JSON payload for a captured shell path identity."""

    if identity is None:
        return None
    return {
        "change_time_ns": identity.change_time_ns,
        "creation_time_ns": identity.creation_time_ns,
        "device": identity.device,
        "inode": identity.inode,
        "mode": identity.mode,
    }


@dataclass(frozen=True, slots=True)
class ShellPathProof:
    """A lexical directory path bound to the target observed during modeling."""

    lexical_path: Path
    resolved_path: Path
    identity: ShellPathIdentity


@dataclass(frozen=True, slots=True)
class NativeRequestContext:
    """Resident-derived context; ``shell`` is the raw wire shell report."""

    context_sha256: str
    admission: Mapping[str, Any]
    shell: Mapping[str, Any] | None
    launch: Mapping[str, Any] | None
    target: str | None
    environment_secret_dump: bool | None = None


_EXECUTABLE_DEFAULTS: Mapping[str, Any] = {
    "command": None,
    "args": (),
    "structured_command": False,
    "direct_executable": False,
    "search_path": None,
    "launch_env": None,
}


def _executable_wire(executable: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Spell out every field the resident defaults.

    The request digest is taken over the typed request the resident decodes, so
    omitted optional fields come back as their defaults and must be sent that
    way or the reply would not bind to what Python hashed.
    """

    if executable is None:
        return None
    return {
        **{key: list(value) if key == "args" else value for key, value in _EXECUTABLE_DEFAULTS.items()},
        **executable,
    }


def native_request_context_build(
    *,
    source: RequestContextSource,
    guard_home: Path | None = None,
    budget_ms: int = _DEFAULT_BUDGET_MS,
    script: str | None = None,
    classify_environment_secrets: bool = False,
    cwd: Path | str | None = None,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
    target: str | None = None,
    policy: Mapping[str, Any] | None = None,
    executable: Mapping[str, Any] | None = None,
) -> NativeRequestContext | NativeRequestContextFailure:
    """Admit the request and build its canonical context in one round trip."""

    try:
        body: dict[str, Any] = {
            "policy": dict(policy) if policy is not None else None,
            "workspace": _absolute_text(workspace),
            "cwd": _absolute_text(cwd),
            "fallback_cwd": _absolute_text(_process_cwd()) if cwd is None else None,
            "home_dir": _absolute_text(home_dir),
            "script": script,
            "target": target,
            "executable": _executable_wire(executable),
        }
        if classify_environment_secrets:
            body["classify_environment_secrets"] = classify_environment_secrets
    except OSError:
        return NativeRequestContextFailure("native_request_context_request_invalid")
    payload = _client._call({"kind": "build", "body": body}, source=source, guard_home=guard_home, budget_ms=budget_ms)
    if isinstance(payload, NativeRequestContextFailure):
        return payload
    decoded = _decode_build(payload)
    return decoded if decoded is not None else NativeRequestContextFailure("native_request_context_payload_invalid")


def _process_cwd() -> Path | None:
    try:
        return Path.cwd()
    except OSError:
        return None


def native_shell_hashes(
    context: Mapping[str, Any],
    segment_index: int | None = None,
    *,
    guard_home: Path | None = None,
    budget_ms: int = _DEFAULT_BUDGET_MS,
) -> tuple[str, str | None, Mapping[str, Any]] | NativeRequestContextFailure:
    """Recompute ``(context_hash, segment_hash, metadata)`` natively."""

    payload = _client._call(
        {"kind": "hash", "body": {"context": dict(context), "segment_index": segment_index}},
        source="hook",
        guard_home=guard_home,
        budget_ms=budget_ms,
    )
    if isinstance(payload, NativeRequestContextFailure):
        return payload
    context_hash, segment_hash, metadata = (
        payload.get("context_hash"),
        payload.get("segment_hash"),
        payload.get("metadata"),
    )
    if (
        set(payload) != {"context_hash", "segment_hash", "metadata"}
        or not isinstance(context_hash, str)
        or _SHA256.fullmatch(context_hash) is None
        or not (segment_hash is None or (isinstance(segment_hash, str) and _SHA256.fullmatch(segment_hash)))
        or not isinstance(metadata, dict)
    ):
        return NativeRequestContextFailure("native_request_context_payload_invalid")
    return context_hash, segment_hash, metadata


_BUILD_KEYS = frozenset({"schema", "admission", "shell", "launch", "target", "context_sha256"})
_SHELL_KEYS = frozenset({"context", "context_hash", "segment_hashes", "metadata"})


def _decode_build(payload: Mapping[str, Any]) -> NativeRequestContext | None:
    if (
        set(payload) not in (_BUILD_KEYS, _BUILD_KEYS | {"environment_secret_dump"})
        or payload["schema"] != _CONTEXT_SCHEMA
    ):
        return None
    digest, admission, shell, launch, target = (
        payload["context_sha256"],
        payload["admission"],
        payload["shell"],
        payload["launch"],
        payload["target"],
    )
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None or not isinstance(admission, dict):
        return None
    if shell is not None and (not isinstance(shell, dict) or set(shell) != _SHELL_KEYS):
        return None
    if shell is not None and not _shell_hashes_valid(shell):
        return None
    if launch is not None and not isinstance(launch, dict):
        return None
    if target is not None and not isinstance(target, str):
        return None
    environment_secret_dump = payload.get("environment_secret_dump")
    if environment_secret_dump is not None and type(environment_secret_dump) is not bool:
        return None
    return NativeRequestContext(digest, admission, shell, launch, target, environment_secret_dump)


def _shell_hashes_valid(shell: Mapping[str, Any]) -> bool:
    context_hash = shell["context_hash"]
    segment_hashes = shell["segment_hashes"]
    context = shell["context"]
    if not isinstance(context_hash, str) or _SHA256.fullmatch(context_hash) is None:
        return False
    if not isinstance(context, dict) or not isinstance(shell["metadata"], dict):
        return False
    segments = context.get("segments")
    if not isinstance(segments, Sequence) or not isinstance(segment_hashes, list):
        return False
    return len(segments) == len(segment_hashes) and all(
        isinstance(item, str) and _SHA256.fullmatch(item) is not None for item in segment_hashes
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
    environment_secret_dump: bool | None = field(default=None, compare=False, repr=False)
    environment_secret_scope: tuple[str, Path | None, Path | None] | None = field(
        default=None, compare=False, repr=False
    )

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
    classify_environment_secrets: bool = False,
) -> ShellExecutionContext:
    """Ask the resident to model literal shell directory changes."""

    result = native_request_context_build(
        source=source,
        script=command_text,
        classify_environment_secrets=classify_environment_secrets,
        cwd=cwd,
        workspace=workspace_root,
        home_dir=home_dir,
    )
    if isinstance(result, NativeRequestContextFailure) or result.shell is None:
        return _unavailable_context(command_text, SHELL_CWD_NATIVE_UNAVAILABLE)
    try:
        return replace(
            _context_from_report(result.shell),
            environment_secret_dump=result.environment_secret_dump,
            environment_secret_scope=(command_text, cwd, home_dir),
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        # A reply that decodes badly is not a context: stay incomplete.
        return _unavailable_context(command_text, SHELL_CWD_NATIVE_UNAVAILABLE)


def _unbound_hash(label: str) -> str:
    return f"{_UNBOUND_PREFIX}{label}"


def shell_execution_context_hash(context: ShellExecutionContext) -> str:
    binding = context.native
    wire = _context_wire(context)
    if binding is not None and dict(binding.wire) == wire:
        return binding.context_hash
    result = native_shell_hashes(wire)
    if isinstance(result, NativeRequestContextFailure):
        return _unbound_hash("shell-context")
    return result[0]
