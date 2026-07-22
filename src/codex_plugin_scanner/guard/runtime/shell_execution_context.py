"""Side-effect-free shell working-directory execution context modeling."""

from __future__ import annotations

import hashlib
import json
import shlex
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from ._shell_execution_context_support import (
    MAX_DIRECTORY_STACK_DEPTH,
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
    DirectoryOperation,
    ShellPathIdentity,
    ShellPathProof,
    control_sequence_reason,
    directory_operation,
    existing_directory,
    is_within,
    last_flow_operator,
    ordered_segments,
    parent_shell_cwd_construct_reason,
    resolve_directory_operand,
    split_shell_tokens,
)


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


@dataclass(frozen=True, slots=True)
class _ShellState:
    cwd: Path | None
    cwd_identity: ShellPathIdentity | None
    cwd_path_proofs: tuple[ShellPathProof, ...]
    cwd_source: str
    stack: tuple[_DirectoryStackEntry, ...]
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class _DirectoryStackEntry:
    cwd: Path
    cwd_identity: ShellPathIdentity
    cwd_path_proofs: tuple[ShellPathProof, ...]


def model_shell_execution_context(
    command_text: str,
    *,
    cwd: Path | None = None,
    workspace_root: Path | None = None,
) -> ShellExecutionContext:
    """Model literal shell directory changes without executing shell code."""

    directory_change_present = bool(SHELL_DIRECTORY_COMMAND.search(command_text))
    initial_input = cwd or Path.cwd()
    root_input = workspace_root or initial_input
    initial_cwd, initial_identity, initial_reason = existing_directory(initial_input)
    root, root_identity, root_reason = existing_directory(root_input)
    reason_code = initial_reason or root_reason
    if reason_code is None and initial_cwd is not None and root is not None and not is_within(initial_cwd, root):
        reason_code = SHELL_CWD_WORKSPACE_ESCAPE
    try:
        tokens = split_shell_tokens(command_text)
    except ValueError:
        return ShellExecutionContext(
            command_text=command_text,
            initial_cwd=initial_cwd,
            workspace_root=root,
            workspace_identity=root_identity,
            segments=(),
            complete=not directory_change_present,
            reason_code=SHELL_CWD_UNRESOLVED_SYNTAX if directory_change_present else None,
            directory_change_present=directory_change_present,
        )

    raw_segments, trailing_controls = ordered_segments(tokens)
    parent_shell_reason = parent_shell_cwd_construct_reason(raw_segments, trailing_controls)
    if parent_shell_reason is not None:
        reason_code = reason_code or parent_shell_reason
        directory_change_present = True
    if not raw_segments:
        return ShellExecutionContext(
            command_text=command_text,
            initial_cwd=initial_cwd,
            workspace_root=root,
            workspace_identity=root_identity,
            segments=(),
            complete=reason_code is None and not directory_change_present,
            reason_code=reason_code or (SHELL_CWD_UNRESOLVED_SYNTAX if directory_change_present else None),
            directory_change_present=directory_change_present,
        )

    state = _ShellState(
        cwd=initial_cwd if reason_code is None else None,
        cwd_identity=initial_identity if reason_code is None else None,
        cwd_path_proofs=(),
        cwd_source="workspace" if cwd is not None else "process",
        stack=(),
        reason_code=reason_code,
    )
    group_states: list[tuple[str, _ShellState | None]] = []
    segments: list[ShellExecutionSegment] = []
    first_reason = reason_code

    for index, (segment_tokens, controls_before) in enumerate(raw_segments):
        controls_after = raw_segments[index + 1][1] if index + 1 < len(raw_segments) else trailing_controls
        state, boundary_reason = _apply_group_boundaries_before_segment(
            state,
            controls_before,
            group_states=group_states,
        )
        segment_reason = state.reason_code or boundary_reason or control_sequence_reason(controls_before)
        operation = directory_operation(segment_tokens)
        if operation is not None:
            directory_change_present = True
            flow_before = last_flow_operator(controls_before)
            previous_segment = segments[-1] if segments else None
            if flow_before in {"&&", "||"} and (
                previous_segment is None
                or previous_segment.directory_operation is None
                or not previous_segment.complete
                or flow_before == "||"
            ):
                operation = replace(operation, reason_code=SHELL_CWD_UNRESOLVED_CONTROL_FLOW)
            segment_reason = segment_reason or operation.reason_code
        segment = ShellExecutionSegment(
            tokens=segment_tokens,
            segment_index=index,
            control_before=controls_before,
            control_after=controls_after,
            effective_cwd=state.cwd,
            cwd_identity=state.cwd_identity,
            cwd_path_proofs=state.cwd_path_proofs,
            cwd_source=state.cwd_source,
            directory_stack=tuple(entry.cwd for entry in state.stack),
            complete=segment_reason is None,
            reason_code=segment_reason,
            directory_operation=operation.name if operation is not None else None,
        )
        if operation is not None:
            state, operation_reason = _apply_directory_operation(
                operation,
                state,
                workspace_root=root,
                controls_before=controls_before,
                controls_after=controls_after,
            )
            if operation_reason is not None:
                segment = replace(segment, complete=False, reason_code=operation_reason)
                segment_reason = operation_reason
        segments.append(segment)
        if first_reason is None and segment_reason is not None:
            first_reason = segment_reason

    _trailing_state, trailing_boundary_reason = _apply_group_boundaries_before_segment(
        state,
        trailing_controls,
        group_states=group_states,
    )
    trailing_reason = trailing_boundary_reason or control_sequence_reason(trailing_controls, trailing=True)
    if trailing_reason is None and any(token in {"(", "{"} for token in trailing_controls):
        trailing_reason = SHELL_CWD_UNRESOLVED_SYNTAX
    if group_states:
        trailing_reason = trailing_reason or SHELL_CWD_UNRESOLVED_SYNTAX
    if first_reason is None and trailing_reason is not None and directory_change_present:
        first_reason = trailing_reason
    complete = first_reason is None
    if directory_change_present and trailing_reason is not None and segments:
        segments[-1] = replace(segments[-1], complete=False, reason_code=trailing_reason)
        complete = False
    return ShellExecutionContext(
        command_text=command_text,
        initial_cwd=initial_cwd,
        workspace_root=root,
        workspace_identity=root_identity,
        segments=tuple(segments),
        complete=complete,
        reason_code=first_reason,
        directory_change_present=directory_change_present,
    )


def validate_shell_execution_segment(
    context: ShellExecutionContext,
    segment: ShellExecutionSegment,
) -> tuple[Path | None, str | None]:
    """Revalidate a modeled cwd immediately before a filesystem-sensitive use."""

    if not segment.complete or segment.effective_cwd is None or segment.cwd_identity is None:
        return None, segment.reason_code or context.reason_code or SHELL_CWD_PATH_CHANGED
    if context.workspace_root is None or context.workspace_identity is None:
        return None, context.reason_code or SHELL_CWD_PATH_CHANGED
    root, root_identity, root_reason = existing_directory(context.workspace_root)
    if root_reason is not None or root_identity != context.workspace_identity:
        return None, SHELL_CWD_PATH_CHANGED
    current, current_identity, current_reason = existing_directory(segment.effective_cwd)
    if current_reason is not None or current_identity != segment.cwd_identity:
        return None, SHELL_CWD_PATH_CHANGED
    if root is None or current is None or not is_within(current, root):
        return None, SHELL_CWD_WORKSPACE_ESCAPE
    for proof in segment.cwd_path_proofs:
        proof_current, proof_identity, proof_reason = existing_directory(proof.lexical_path)
        if proof_reason is not None or proof_current != proof.resolved_path or proof_identity != proof.identity:
            return None, SHELL_CWD_PATH_CHANGED
    return current, None


def shell_execution_segment_hash(
    context: ShellExecutionContext,
    segment: ShellExecutionSegment,
) -> str:
    """Return an approval-safe identity for one segment and its full command."""

    payload = {
        "schema": "shell-execution-context-v1",
        "command": context.command_text,
        "workspace_root": str(context.workspace_root) if context.workspace_root is not None else None,
        "workspace_identity": _identity_payload(context.workspace_identity),
        "segment": _segment_payload(segment),
    }
    return _sha256_payload(payload)


def shell_execution_context_hash(context: ShellExecutionContext) -> str:
    payload = {
        "schema": "shell-execution-context-v1",
        "command": context.command_text,
        "initial_cwd": str(context.initial_cwd) if context.initial_cwd is not None else None,
        "workspace_root": str(context.workspace_root) if context.workspace_root is not None else None,
        "workspace_identity": _identity_payload(context.workspace_identity),
        "complete": context.complete,
        "reason_code": context.reason_code,
        "segments": [_segment_payload(segment) for segment in context.segments],
    }
    return _sha256_payload(payload)


def shell_execution_context_metadata(context: ShellExecutionContext) -> dict[str, object]:
    """Return bounded metadata suitable for runtime artifacts and approval identity."""

    effective_cwds = [str(path) for path in context.effective_cwds]
    return {
        "shell_execution_context_hash": context.context_hash,
        "shell_execution_context_complete": context.complete,
        "shell_execution_context_reason_code": context.reason_code,
        "shell_execution_effective_cwds": effective_cwds,
        "effective_cwd": effective_cwds[-1] if effective_cwds else None,
    }


def _apply_group_boundaries_before_segment(
    state: _ShellState,
    controls: tuple[str, ...],
    *,
    group_states: list[tuple[str, _ShellState | None]],
) -> tuple[_ShellState, str | None]:
    reason: str | None = None
    for control in controls:
        if control == "(":
            group_states.append(("(", state))
        elif control == "{":
            group_states.append(("{", None))
        elif control == ")":
            if not group_states or group_states[-1][0] != "(":
                reason = SHELL_CWD_UNRESOLVED_SYNTAX
            else:
                _group, saved_state = group_states.pop()
                if saved_state is not None:
                    state = saved_state
        elif control == "}":
            if not group_states or group_states[-1][0] != "{":
                reason = SHELL_CWD_UNRESOLVED_SYNTAX
            else:
                group_states.pop()
    return state, reason


def _apply_directory_operation(
    operation: DirectoryOperation,
    state: _ShellState,
    *,
    workspace_root: Path | None,
    controls_before: tuple[str, ...],
    controls_after: tuple[str, ...],
) -> tuple[_ShellState, str | None]:
    if operation.reason_code is not None:
        return replace(state, cwd=None, cwd_identity=None, reason_code=operation.reason_code), operation.reason_code
    if state.cwd is None or state.cwd_identity is None or workspace_root is None:
        reason = state.reason_code or SHELL_CWD_UNRESOLVED_CONTROL_FLOW
        return replace(state, reason_code=reason), reason
    if operation.name == "popd":
        if not state.stack:
            reason = SHELL_CWD_AMBIGUOUS_STACK
            return replace(state, cwd=None, cwd_identity=None, reason_code=reason), reason
        stack_entry = state.stack[-1]
        next_state = _ShellState(
            cwd=stack_entry.cwd,
            cwd_identity=stack_entry.cwd_identity,
            cwd_path_proofs=stack_entry.cwd_path_proofs,
            cwd_source="shell_popd",
            stack=state.stack[:-1],
        )
    else:
        if operation.operand is None:
            return replace(state, cwd=None, cwd_identity=None, reason_code=SHELL_CWD_UNRESOLVED_EXPRESSION), (
                SHELL_CWD_UNRESOLVED_EXPRESSION
            )
        destination, destination_identity, destination_proof, reason = resolve_directory_operand(
            operation.operand,
            current_cwd=state.cwd,
            workspace_root=workspace_root,
        )
        if reason is not None or destination is None or destination_identity is None or destination_proof is None:
            failure_reason = reason or SHELL_CWD_MISSING_DIRECTORY
            return replace(state, cwd=None, cwd_identity=None, reason_code=failure_reason), failure_reason
        stack = state.stack
        if operation.name == "pushd":
            if len(stack) >= MAX_DIRECTORY_STACK_DEPTH:
                return replace(state, cwd=None, cwd_identity=None, reason_code=SHELL_CWD_STACK_LIMIT), (
                    SHELL_CWD_STACK_LIMIT
                )
            stack = (
                *stack,
                _DirectoryStackEntry(
                    cwd=state.cwd,
                    cwd_identity=state.cwd_identity,
                    cwd_path_proofs=state.cwd_path_proofs,
                ),
            )
        next_state = _ShellState(
            cwd=destination,
            cwd_identity=destination_identity,
            cwd_path_proofs=(*state.cwd_path_proofs, destination_proof),
            cwd_source=f"shell_{operation.name}",
            stack=stack,
        )
    flow_before = last_flow_operator(controls_before)
    flow = last_flow_operator(controls_after)
    if flow_before in {"|", "|&"}:
        return state, None
    if flow in {"|", "|&", "&"}:
        return state, None
    if flow == "||":
        reason = SHELL_CWD_UNRESOLVED_CONTROL_FLOW
        return replace(next_state, cwd=None, cwd_identity=None, reason_code=reason), reason
    return next_state, None


def _identity_payload(identity: ShellPathIdentity | None) -> dict[str, int] | None:
    if identity is None:
        return None
    return {
        "change_time_ns": identity.change_time_ns,
        "creation_time_ns": identity.creation_time_ns,
        "device": identity.device,
        "inode": identity.inode,
        "mode": identity.mode,
    }


def _segment_payload(segment: ShellExecutionSegment) -> dict[str, object]:
    return {
        "tokens": list(segment.tokens),
        "segment_index": segment.segment_index,
        "control_before": list(segment.control_before),
        "control_after": list(segment.control_after),
        "effective_cwd": str(segment.effective_cwd) if segment.effective_cwd is not None else None,
        "cwd_identity": _identity_payload(segment.cwd_identity),
        "cwd_path_proofs": [
            {
                "lexical_path": str(proof.lexical_path),
                "resolved_path": str(proof.resolved_path),
                "identity": _identity_payload(proof.identity),
            }
            for proof in segment.cwd_path_proofs
        ],
        "cwd_source": segment.cwd_source,
        "directory_stack": [str(path) for path in segment.directory_stack],
        "complete": segment.complete,
        "reason_code": segment.reason_code,
        "directory_operation": segment.directory_operation,
    }


def _sha256_payload(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


__all__ = [
    "SHELL_CWD_AMBIGUOUS_STACK",
    "SHELL_CWD_MISSING_DIRECTORY",
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
    "ShellExecutionContext",
    "ShellExecutionSegment",
    "model_shell_execution_context",
    "shell_execution_context_hash",
    "shell_execution_context_metadata",
    "shell_execution_segment_hash",
    "validate_shell_execution_segment",
]
